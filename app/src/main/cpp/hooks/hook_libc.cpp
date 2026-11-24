#include "hook_libc.h"
#include "../utils/log.h"

#include <bytehook.h>

#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>


#include <sys/prctl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

#include <mutex>
#include <set>
#include <string>
#include <utility>

#ifndef O_TMPFILE
#define O_TMPFILE 020000000
#endif

extern "C" int __system_property_get(const char* name, char* value);

namespace hook_libc {

// ---------------------------------------------------------------------------
// 配置（由 Java 层注入）
// ---------------------------------------------------------------------------

static bool g_probe = true;
static char g_fake_serial[128] = {0};
static char g_fake_soc[128] = {0};
static char g_boot_state[32] = "green";
static char g_rom_host[128] = {0};
static char g_rom_user[128] = {0};
static char g_rom_display[128] = {0};
static char g_rom_fingerprint[256] = {0};

// 完整环境画像
static bool g_env_on = false;
// true = 不做 maps/smaps 行过滤（保留给实验切换用）
static bool g_nofilter_maps = false;
static char g_env[19][256];

// 调用者归因开关（观测用，默认开；deep=对 libc 中转层做帧指针回溯）
static bool g_attr_on = false;
static bool g_attr_deep = false;

void set_attr_config(bool enabled, bool deep) {
    g_attr_on = enabled;
    g_attr_deep = deep;
    LOGI("Caller attribution: enabled=%d deep=%d", (int)enabled, (int)deep);
}

void set_env_profile(const char* profile) {
    for (int i = 0; i < 19; i++) g_env[i][0] = 0;
    g_env_on = false;
    if (!profile || !profile[0]) return;

    const char* p = profile;
    for (int i = 0; i < 19 && p; i++) {
        const char* bar = strchr(p, '|');
        size_t len = bar ? (size_t)(bar - p) : strlen(p);
        if (len >= sizeof(g_env[i])) len = sizeof(g_env[i]) - 1;
        memcpy(g_env[i], p, len);
        g_env[i][len] = 0;
        p = bar ? bar + 1 : nullptr;
    }
    g_env_on = true;
    LOGI("Env profile enabled: release=%s sdk=%s build=%s display=%s", g_env[0], g_env[1],
         g_env[2], g_env[3]);
}

bool probe_enabled() { return g_probe; }
const char* fake_serial() { return g_fake_serial; }
const char* fake_soc() { return g_fake_soc; }
const char* boot_state() { return g_boot_state; }

void set_config(bool probe, const char* fake_serial, const char* fake_soc,
                const char* boot_state, const char* rom_host, const char* rom_user,
                const char* rom_display, const char* rom_fingerprint) {
    g_probe = probe;
    auto copy_str = [](char* dst, size_t cap, const char* src) {
        if (src) {
            strncpy(dst, src, cap - 1);
            dst[cap - 1] = 0;
        } else {
            dst[0] = 0;
        }
    };
    copy_str(g_fake_serial, sizeof(g_fake_serial), fake_serial);
    copy_str(g_fake_soc, sizeof(g_fake_soc), fake_soc);
    copy_str(g_boot_state, sizeof(g_boot_state), boot_state);
    copy_str(g_rom_host, sizeof(g_rom_host), rom_host);
    copy_str(g_rom_user, sizeof(g_rom_user), rom_user);
    copy_str(g_rom_display, sizeof(g_rom_display), rom_display);
    copy_str(g_rom_fingerprint, sizeof(g_rom_fingerprint), rom_fingerprint);
}

// 探测日志限流：每个路径只打一次，避免 /proc/*/cmdline 扫描刷屏
static std::mutex g_probe_mutex;
static std::set<std::string> g_probe_seen;
static std::set<std::string> g_faked_seen;
static thread_local bool t_in_syscall = false;
// .android_lq 写入 fd 跟踪（open 记录 → fake_write 抓内容）
static thread_local int t_lq_write_fd = -1;

static bool is_probe_path(const char* p) {
    if (!p) return false;
    // 审计用：覆盖所有可能暴露设备标识的来源。
    // 之前只白名单了 /proc、soc0、selinux、adb —— 恰好漏掉 MAC、cpuinfo、
    // 存储序列号、蓝牙配置这些地方，正是"环境隐藏没做好"的候选。
    static const char* pats[] = {
        "/proc/",                    // maps/status/version/cpuinfo/cmdline/device-tree...
        "/sys/class/net",            // wlan0/bt MAC
        "/sys/block",                // 存储 serial/wwid
        "/sys/devices/soc0",         // SoC serial/soc_id/machine
        "/sys/devices/system/cpu",   // CPU 拓扑
        "/sys/fs/selinux",           // SELinux
        "/sys/module",               // 内核模块
        "/dev/",                     // 设备节点
        "/data/adb",
        "/data/local",
        "/data/misc/bluetooth",
        "/data/misc/wifi",
        "/data/vendor",
        "/system/xbin", "/system/bin/su", "/sbin/su",
        // fekit 设备身份锚：65B 恒定值，跨会话不变。
        // 观察它的 open（若走 libc）就能定位写入者并在上游拦截。
        ".android_lq",
        nullptr
    };
    for (int i = 0; pats[i]; i++) {
        if (strstr(p, pats[i])) return true;
    }
    return false;
}

static void probe_log_path(const char* path) {
    if (!g_probe || !path || !is_probe_path(path)) return;
    std::lock_guard<std::mutex> lock(g_probe_mutex);
    if (g_probe_seen.size() >= 1200) return;
    if (g_probe_seen.insert(path).second) {
        LOGI("PROBE open: %s", path);
    }
}

static void log_faked_once(const char* what, const char* path) {
    std::lock_guard<std::mutex> lock(g_probe_mutex);
    if (g_faked_seen.size() >= 200) return;
    if (g_faked_seen.insert(std::string(what) + path).second) {
        LOGI("Faked %s: %s", what, path);
    }
}

// ---------------------------------------------------------------------------
// 调用者归因（caller attribution）
// 目的：libfekit 的检测逻辑跑在它自己的字节码 VM 里（sub_1401B8 dispatch 循环 +
// unk_43F8A1 字节码），静态分析看不到正常的检测调用图，hook 它的 C++ 函数也没用。
// 唯一还能拿到的事实是"它向 libc 要了哪些东西"。所以每个 hook 入口在 LR 还没被
// 覆盖时就取一次 return address，用 dl_iterate_phdr 缓存的模块区间判定归属。
// 纯观测：不改返回值、不改 errno、不影响 QQ 自身的判断。
//
// 两级归因：
//   d=0  __builtin_return_address(0) 直接落在 fekit/turing/msf —— 最常见
//   d>0  RA 落在 libc/libbytehook 这类中转层时，用 bionic backtrace() 往上找
//        第一个非中转层的帧（结果按 RA 缓存，每个调用点只回溯一次）
//
// 输出：FKCALL <fn> mod=<leaf>+0x<off> d=<depth> act=<fake|pass|deny|fail|prop> path=/...
//
// 记录策略：
//   - 调用者是 libfekit / libturing* / libMSF → 无条件记录（这才是"它读了什么"的全集，
//     包括不在探测名单里的普通路径）
//   - 其他调用者只在路径属于检测敏感面（is_probe_path / is_hidden_path / prop）时记录，
//     否则 QQ 自己的普通文件读取会刷屏
// ---------------------------------------------------------------------------

static bool is_probe_prop(const char* name);
static bool is_hidden_path(const char* p);

#define ATTR_MAX_MODS 512
#define ATTR_CACHE_SZ 512
#define ATTR_MAX_RECORDS 4000
#define ATTR_MAX_DEEP 1200
// 重解析总次数上限 + 两次解析之间的最小间隔。
// 之前只给了 8 次"未命中就重解析"，启动早期 JIT/vDSO 地址会立刻把配额烧光，
// libfekit 运行期 dlopen 进来之后再也没被解析过，归因全变成 "?"。
#define ATTR_MAX_RESOLVES 64
#define ATTR_RESOLVE_INTERVAL_MS 250

struct ModEntry {
    uintptr_t lo;
    uintptr_t hi;
    int kind;  // 0=other 1=libfekit 2=libturing* 4=libMSF
    char name[52];
};

struct AttrHit {
    uintptr_t base;
    uintptr_t off;
    int kind;
    int depth;
    char mod[52];
};

// 已发布的模块表：g_mods_lock 只保护这一段纯内存的拷贝/比较。
// 锁序铁律：持 g_mods_lock 时绝不调用 dl_iterate_phdr/任何外部函数 —— 否则会和
// linker 锁形成 ABBA（linker 线程 dlopen 里调 open -> 我们的 hook -> 要 g_mods_lock）。
static ModEntry g_mods[ATTR_MAX_MODS];
static int g_mods_n = 0;
static std::mutex g_mods_lock;

// 解析快照：只有拿得到 g_resolve_lock 的线程才能动；
// 用 try_lock 而不是 lock，保证"解析者等 linker 锁、linker 持有者等 g_resolve_lock"不会互锁。
static ModEntry g_snap[ATTR_MAX_MODS];
static std::mutex g_resolve_lock;
static int g_mods_resolves = 0;
static uint64_t g_last_resolve_ms = 0;
static int g_attr_deep_count = 0;

static std::mutex g_attr_mutex;
static std::set<std::string> g_attr_records;

// 调用点缓存：无锁读。tag 最后写入，读到时其余字段已就绪。
struct AttrSlot {
    uintptr_t tag;  // = 调用点 RA，0 表示空
    AttrHit hit;
};

static AttrSlot g_attr_cache[ATTR_CACHE_SZ];

static int mod_kind_of(const char* nm) {
    if (!nm) return 0;
    int k = 0;
    if (strstr(nm, "libfekit")) k |= 1;
    if (strstr(nm, "libturing")) k |= 2;
    if (strstr(nm, "libMSF") || strstr(nm, "libmsf")) k |= 4;
    return k;
}

// 中转层：libc 包装函数（fopen -> openat）、bytehook 代理、我们自己的模块
static bool mod_is_relay(const char* nm) {
    if (!nm) return true;
    static const char* relay[] = {
        "libc.so", "libc++.so", "libdl.so", "libld-android.so", "libbytehook.so",
        "native-bypass.so", "libunwind", "libart.so", "libnativeloader.so", nullptr
    };
    for (int i = 0; relay[i]; i++) {
        if (strstr(nm, relay[i])) return true;
    }
    return false;
}

struct SnapCursor {
    ModEntry* e;
    int* n;
};

static int mod_collect_cb(struct dl_phdr_info* info, size_t sz, void* data) {
    (void) sz;
    SnapCursor* cur = reinterpret_cast<SnapCursor*>(data);
    if (!info || !cur) return 1;
    if (*(cur->n) >= ATTR_MAX_MODS) return 1;

    uintptr_t lo = (uintptr_t) info->dlpi_addr;
    uintptr_t hi = lo;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t end = lo + (uintptr_t) ph->p_vaddr + (uintptr_t) ph->p_memsz;
        if (end > hi) hi = end;
    }
    if (hi <= lo) return 0;

    char leaf[52];
    const char* nm = info->dlpi_name;
    if (nm && nm[0]) {
        const char* slash = strrchr(nm, '/');
        snprintf(leaf, sizeof(leaf), "%s", slash ? slash + 1 : nm);
    } else {
        snprintf(leaf, sizeof(leaf), "%s", "[main]");
    }

    ModEntry& e = cur->e[(*cur->n)++];
    e.lo = lo;
    e.hi = hi;
    e.kind = mod_kind_of(leaf);
    memcpy(e.name, leaf, sizeof(e.name));
    return 0;
}

static uint64_t attr_now_ms() {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t) ts.tv_sec * 1000ull + (uint64_t) (ts.tv_nsec / 1000000);
}

static void mod_resolve() {
    if (!g_resolve_lock.try_lock()) return;
    int n = 0;
    SnapCursor cur = {g_snap, &n};
    dl_iterate_phdr(mod_collect_cb, &cur);
    {
        std::lock_guard<std::mutex> lk(g_mods_lock);
        memcpy(g_mods, g_snap, sizeof(ModEntry) * (size_t) n);
        __atomic_store_n(&g_mods_n, n, __ATOMIC_RELEASE);
    }
    __atomic_store_n(&g_last_resolve_ms, attr_now_ms(), __ATOMIC_RELAXED);
    g_mods_resolves++;
    g_resolve_lock.unlock();
}

// 未命中时按时间节流重解析：libfekit/libturing 是运行期才 dlopen 进来的，
// 必须保证整个启动/登录过程里都能持续刷新模块表，而不是前 8 次就收手。
static bool attr_may_resolve() {
    int resolves = __atomic_load_n(&g_mods_resolves, __ATOMIC_RELAXED);
    if (resolves >= ATTR_MAX_RESOLVES) return false;
    uint64_t t = attr_now_ms();
    if (t == 0) return resolves == 0;
    uint64_t last = __atomic_load_n(&g_last_resolve_ms, __ATOMIC_RELAXED);
    return last == 0 || (t - last) >= ATTR_RESOLVE_INTERVAL_MS;
}

// 只在 g_mods_lock 时调用，返回时把副本给出（避免出锁后读到被替换的表）
static bool mod_lookup_copy(uintptr_t a, ModEntry* out) {
    std::lock_guard<std::mutex> lk(g_mods_lock);
    int n = __atomic_load_n(&g_mods_n, __ATOMIC_ACQUIRE);
    for (int i = 0; i < n; i++) {
        if (a >= g_mods[i].lo && a < g_mods[i].hi) {
            *out = g_mods[i];
            return true;
        }
    }
    return false;
}

static void attr_fill(AttrHit* out, const ModEntry* e, uintptr_t a, int depth) {
    out->base = e->lo;
    out->off = a - e->lo;
    out->kind = e->kind;
    out->depth = depth;
    memcpy(out->mod, e->name, sizeof(out->mod));
}

static void attr_compute(uintptr_t a, AttrHit* out) {
    memset(out, 0, sizeof(*out));
    out->off = a;
    memcpy(out->mod, "?", 2);
    if (a == 0) return;

    if (__atomic_load_n(&g_mods_n, __ATOMIC_ACQUIRE) == 0) mod_resolve();

    ModEntry e;
    if (mod_lookup_copy(a, &e)) {
        attr_fill(out, &e, a, 0);
        return;
    }
    // hooks 装好之后才 dlopen 进来的库：按时间节流重解析
    if (attr_may_resolve()) {
        mod_resolve();
        if (mod_lookup_copy(a, &e)) attr_fill(out, &e, a, 0);
    }
}

// ---- 深归因：RA 落在 libc/bytehook 这类中转层时，顺着帧指针找真实发起方 ----
//
// CFI unwinding previously faulted on ART execute-only JIT code pages. Keep
// this optional path disabled in the default configuration; do not run it while
// validating the file recovery.
#if defined(__aarch64__) || defined(__arm__)
#define ATTR_HAVE_FP_WALK 1
#endif

static int attr_walk_frames(uintptr_t* out, int max) {
#ifdef ATTR_HAVE_FP_WALK
    uintptr_t fp = (uintptr_t) __builtin_frame_address(0);
    int n = 0;
    for (int i = 0; i < max; i++) {
        if (fp == 0 || (fp & (sizeof(uintptr_t) - 1)) != 0) break;
        uintptr_t next = *(const uintptr_t*) fp;
        uintptr_t lr = *(const uintptr_t*) (fp + sizeof(uintptr_t));
        if (lr > 0x1000) out[n++] = lr;
        if (next <= fp || (next - fp) > (1u << 20)) break;
        fp = next;
    }
    return n;
#else
    (void) out;
    (void) max;
    return 0;
#endif
}

static bool attr_deep_lookup(uintptr_t a, AttrHit* out) {
    if (!g_attr_deep) return false;

    uintptr_t frames[24];
    {
        std::lock_guard<std::mutex> lk(g_attr_mutex);
        if (g_attr_deep_count >= ATTR_MAX_DEEP) return false;
        g_attr_deep_count++;
    }

    int n = attr_walk_frames(frames, (int) (sizeof(frames) / sizeof(frames[0])));
    if (n <= 1) return false;

    for (int i = 1; i < n; i++) {
        uintptr_t f = frames[i];
        ModEntry e;
        if (!mod_lookup_copy(f, &e)) continue;
        if (e.kind != 0 || !mod_is_relay(e.name)) {
            attr_fill(out, &e, f, i);
            return true;
        }
    }
    return false;
}

static bool attr_cache_get(uintptr_t a, AttrHit* out) {
    AttrSlot& s = g_attr_cache[((a >> 2) ^ (a >> 15)) & (ATTR_CACHE_SZ - 1)];
    if (__atomic_load_n(&s.tag, __ATOMIC_ACQUIRE) != a) return false;
    memcpy(out, &s.hit, sizeof(*out));
    return true;
}

static void attr_cache_put(uintptr_t a, const AttrHit* in) {
    if (a == 0) return;
    AttrSlot& s = g_attr_cache[((a >> 2) ^ (a >> 15)) & (ATTR_CACHE_SZ - 1)];
    memcpy(&s.hit, in, sizeof(s.hit));
    __atomic_store_n(&s.tag, a, __ATOMIC_RELEASE);
}

static bool attr_path_interesting(const char* p, bool is_prop) {
    if (!p || !p[0]) return false;
    if (is_prop) return is_probe_prop(p);
    return is_probe_path(p) || is_hidden_path(p);
}

// 记录一次 libc 访问的归属。fn 用 libc 入口名（open/openat/fopen/access/stat/prop）
static void attr_report(const char* fn, const char* what, const char* act, void* raw_ra) {
    if (!g_attr_on || !what || !what[0]) return;

    uintptr_t ra = (uintptr_t) raw_ra;
    bool is_prop = (strcmp(fn, "prop") == 0);
    bool interesting = attr_path_interesting(what, is_prop);

    AttrHit hit;
    if (!attr_cache_get(ra, &hit)) {
        attr_compute(ra, &hit);
        if (hit.kind == 0 && interesting) {
            AttrHit deep;
            if (attr_deep_lookup(ra, &deep)) hit = deep;
        }
        attr_cache_put(ra, &hit);
    }

    if (hit.kind == 0 && !interesting) return;

    char key[320];
    snprintf(key, sizeof(key), "%s|%s|0x%zx|%s|%s", fn, hit.mod, (size_t) hit.off, act, what);

    {
        std::lock_guard<std::mutex> lk(g_attr_mutex);
        if (g_attr_records.size() >= ATTR_MAX_RECORDS) return;
        if (!g_attr_records.insert(key).second) return;
    }

    char pbuf[224];
    size_t plen = strlen(what);
    if (plen >= sizeof(pbuf)) plen = sizeof(pbuf) - 1;
    memcpy(pbuf, what, plen);
    pbuf[plen] = 0;

    LOGI("FKCALL %s mod=%s+0x%zx d=%d act=%s %s=%s", fn, hit.mod, (size_t) hit.off, hit.depth,
         act, is_prop ? "prop" : "path", pbuf);
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// .android_lq 伪造值管理：首次生成随机 65B 并持久化，之后复用
// ---------------------------------------------------------------------------

#define FAKE_LQ_PATH "/data/user/0/com.tencent.mobileqq/files/.android_lq.fake"
#define FAKE_LQ_LEN 65

static std::mutex g_lq_mutex;
static char g_fake_lq[FAKE_LQ_LEN];
static bool g_fake_lq_ready = false;

static bool get_fake_lq(std::string& out) {
    std::lock_guard<std::mutex> lk(g_lq_mutex);
    if (!g_fake_lq_ready) {
        // 尝试读已持久化的值
        int fd = (int) syscall(__NR_openat, AT_FDCWD, FAKE_LQ_PATH, O_RDONLY, 0);
        if (fd >= 0) {
            char buf[FAKE_LQ_LEN];
            ssize_t n = 0, r;
            while (n < FAKE_LQ_LEN && (r = (ssize_t) syscall(__NR_read, fd, buf + n,
                                                             (size_t)(FAKE_LQ_LEN - n))) > 0) {
                n += r;
            }
            syscall(__NR_close, fd);
            if (n == FAKE_LQ_LEN) {
                memcpy(g_fake_lq, buf, FAKE_LQ_LEN);
                g_fake_lq_ready = true;
            }
        }
        if (!g_fake_lq_ready) {
            // 生成随机 65B：/dev/urandom
            int ufd = (int) syscall(__NR_openat, AT_FDCWD, "/dev/urandom", O_RDONLY, 0);
            if (ufd >= 0) {
                size_t got = 0;
                while (got < FAKE_LQ_LEN) {
                    ssize_t r = (ssize_t) syscall(__NR_read, ufd, g_fake_lq + got,
                                                  (size_t)(FAKE_LQ_LEN - got));
                    if (r <= 0) break;
                    got += (size_t) r;
                }
                syscall(__NR_close, ufd);
            } else {
                // 兜底：伪随机
                uint64_t t;
                struct timespec ts;
                clock_gettime(CLOCK_MONOTONIC, &ts);
                t = (uint64_t) ts.tv_nsec ^ ((uint64_t) getpid() << 32);
                for (int i = 0; i < FAKE_LQ_LEN; i++) {
                    t = t * 6364136223846793005ULL + 1442695040888963407ULL;
                    g_fake_lq[i] = (char) (t >> 33);
                }
            }
            // 持久化（写模式 openat 直通 syscall）
            int wfd = (int) syscall(__NR_openat, AT_FDCWD, FAKE_LQ_PATH,
                                    O_WRONLY | O_CREAT | O_TRUNC, 0600);
            if (wfd >= 0) {
                size_t done = 0;
                while (done < FAKE_LQ_LEN) {
                    ssize_t w = (ssize_t) syscall(__NR_write, wfd, g_fake_lq + done,
                                                  (size_t)(FAKE_LQ_LEN - done));
                    if (w <= 0) break;
                    done += (size_t) w;
                }
                syscall(__NR_close, wfd);
            }
            g_fake_lq_ready = true;
        }
        LOGI("FAKE .android_lq ready (persisted=%d)", (int) g_fake_lq_ready);
    }
    out.assign(g_fake_lq, FAKE_LQ_LEN);
    return true;
}


// 真实文件读取：直接走 syscall，绕过所 hook，避免递归
// ---------------------------------------------------------------------------

static bool read_real_file(const char* path, std::string& out) {
    t_in_syscall = true;
    int fd = (int)syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) {
        t_in_syscall = false;
        return false;
    }
    char buf[8192];
    ssize_t n;
    while ((n = (ssize_t)syscall(__NR_read, fd, buf, sizeof(buf))) > 0) {
        out.append(buf, (size_t)n);
    }
    syscall(__NR_close, fd);
    t_in_syscall = false;
    return true;
}

// ---------------------------------------------------------------------------
// 伪造文件内容
// ---------------------------------------------------------------------------

enum FakeKind {
    FK_NONE = 0,
    FK_MAPS,
    FK_SMAPS,
    FK_MOUNTINFO,
    FK_STATUS,
    FK_BOOTCONFIG,
    FK_CPUINFO,
    FK_SOC_SERIAL,
    FK_VERSION,
    FK_CMDLINE,
    // /proc/net/unix：fekit 的 fopen(+0x386df8) 会读它找抽象 socket 名。
    // 实测本机 /proc/<pid>/net/unix 里能看到 `/lspd`（LSPosed daemon 的
    // abstract socket），这是 libc 层唯一还没堵的 root 框架指纹。
    FK_NET_UNIX,
    // 【V9】/proc/<other_pid>/cmdline：QQ 可扫其他进程名看到 magiskd/ksud。
    FK_PROC_CMDLINE,
};

static bool ends_with(const char* s, const char* suffix) {
    if (!s || !suffix) return false;
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && strcmp(s + ls - lf, suffix) == 0;
}

static bool is_proc_path(const char* p) {
    return p && strncmp(p, "/proc/", 6) == 0;
}

static bool is_self_proc_path(const char* p) {
    if (!p) return false;
    if (strstr(p, "/proc/self/") || strstr(p, "/proc/thread-self/")) return true;
    char prefix[40];
    snprintf(prefix, sizeof(prefix), "/proc/%d/", getpid());
    return strncmp(p, prefix, strlen(prefix)) == 0;
}

static bool is_root_process_name(const char* s) {
    if (!s || !s[0]) return false;
    static const char* names[] = {
        "magiskd", "magisk", "ksud", "kernelsu", "apd", "apatch",
        "daemonsu", "su", "supersu", "shamiko", "lspd", "lsposed",
        "vectord", "zygiskd", nullptr
    };
    for (int i = 0; names[i]; i++) {
        if (strcmp(s, names[i]) == 0) return true;
    }
    return false;
}

static FakeKind classify_path(const char* p) {
    if (!p) return FK_NONE;

    if (is_proc_path(p)) {
        if (ends_with(p, "/maps")) return FK_MAPS;
        if (ends_with(p, "/smaps")) return FK_SMAPS;
        if (ends_with(p, "/mountinfo")) return FK_MOUNTINFO;
        if (ends_with(p, "/net/unix")) return FK_NET_UNIX;
    // /proc/<数字>/cmdline（注意排除 /proc/self/ 和 /proc/<自己的pid>/，
    // 那些走别的分支处理）
    if (ends_with(p, "/cmdline")) {
        const char* c = strstr(p, "/proc/");
        if (c) {
            const char* q = c + 6;
            if (*q >= '0' && *q <= '9') return FK_PROC_CMDLINE;
        }
    }
        if (ends_with(p, "/status") && is_self_proc_path(p)) return FK_STATUS;
    }
    if (strcmp(p, "/proc/bootconfig") == 0) return FK_BOOTCONFIG;
    if (strcmp(p, "/proc/cpuinfo") == 0) return FK_CPUINFO;
    if (strcmp(p, "/proc/version") == 0) return FK_VERSION;
    if (strcmp(p, "/proc/cmdline") == 0) return FK_CMDLINE;
    if (strcmp(p, "/sys/devices/soc0/serial_number") == 0) return FK_SOC_SERIAL;
    return FK_NONE;
}

// hook 特征黑名单（maps / smaps / mountinfo 共用）
static const char* kBlacklist[] = {
    "lsposed", "lspd", "xposed", "edxposed", "riru", "zygisk", "susfs",
    "kernelsu", "apatch", "magisk", "frida", "substrate", "bytehook",
    "qqnativeguard", "native-bypass", "qfun", "sandhook", "lspatch",
    "libwhale", "libkpatch", "data/adb", nullptr
};

static bool line_blocked(const std::string& line) {
    for (int i = 0; kBlacklist[i]; i++) {
        if (line.find(kBlacklist[i]) != std::string::npos) return true;
    }
    return false;
}

static std::string filter_lines(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t pos = 0;
    while (pos < in.size()) {
        size_t e = in.find('\n', pos);
        if (e == std::string::npos) {
            std::string line = in.substr(pos);
            if (!line_blocked(line)) out += line;
            break;
        }
        std::string line = in.substr(pos, e - pos);
        if (!line_blocked(line)) {
            out += line;
            out += '\n';
        }
        pos = e + 1;
    }
    return out;
}

//  s 中所 key（形 "androidboot.xxx="）的值替换为 value
static void replace_token_value(std::string& s, const char* key, const std::string& value) {
    size_t klen = strlen(key);
    size_t pos = 0;
    while ((pos = s.find(key, pos)) != std::string::npos) {
        size_t vstart = pos + klen;
        size_t vend = s.find(' ', vstart);
        if (vend == std::string::npos) vend = s.size();
        s.replace(vstart, vend - vstart, value);
        pos = vstart + value.size();
    }
}

static void sanitize_cmdline(std::string& s) {
    if (g_boot_state[0]) {
        replace_token_value(s, "androidboot.verifiedbootstate=", g_boot_state);
    }
    if (g_fake_serial[0]) {
        replace_token_value(s, "androidboot.serialno=", g_fake_serial);
    }
    replace_token_value(s, "androidboot.flash.locked=", "1");
    replace_token_value(s, "androidboot.warranty_bit=", "0");
    replace_token_value(s, "androidboot.vbmeta.device_state=", "locked");
    replace_token_value(s, "androidboot.veritymode=", "enforcing");
    if (g_env_on) {
        replace_token_value(s, "androidboot.type=", "release");
        replace_token_value(s, "androidboot.bootreason=", "reboot");
        replace_token_value(s, "androidboot.verifiedbootstate=", "green");
        replace_token_value(s, "androidboot.flash.locked=", "1");

        // 【V8 补全】以下 token 实测存在于 /proc/cmdline，会暴露真机身份。
        // 尤其 project_codename=lemonadep 直接等于 OnePlus 9 Pro 代号，
        // 与任何伪造机型矛盾；platform_name=SM835 同理。
        replace_token_value(s, "androidboot.project_codename=", "pgem10");
        replace_token_value(s, "androidboot.platform_name=", "SM8650");
        replace_token_value(s, "androidboot.platform_id=", "0");
        replace_token_value(s, "androidboot.prjname=", "0");
        replace_token_value(s, "androidboot.hw_version=", "0");
        replace_token_value(s, "androidboot.rf_version=", "0");
        replace_token_value(s, "androidboot.prj_version=", "0");
        replace_token_value(s, "androidboot.secboot=", "enabled");
        replace_token_value(s, "androidboot.at_location=", "factory");
        replace_token_value(s, "androidboot.rpmb_enable=", "true");
        replace_token_value(s, "androidboot.prmec=", "true");
        replace_token_value(s, "androidboot.opcarrier=", "none");
        replace_token_value(s, "androidboot.bootcount=", "");
        replace_token_value(s, "androidboot.power_cut_test=", "");
        replace_token_value(s, "androidboot.cust=", "");
        replace_token_value(s, "androidboot.startupmode=", "reboot");
        replace_token_value(s, "androidboot.mode=", "normal");
        replace_token_value(s, "androidboot.force_normal_boot=", "1");
        replace_token_value(s, "androidboot.slot_suffix=", "_a");
        replace_token_value(s, "lk_version=", "V1.0");
        replace_token_value(s, "buildvariant=", "user");
        replace_token_value(s, "smooth_soc_switch=", "");
        replace_token_value(s, "saupwk.en=", "1");
        // OPPO 特有参数，伪造机型必须保留但去掉真机项目号
        replace_token_value(s, "phx_rus_conf.main_on=", "1");
        replace_token_value(s, "phx_rus_conf.recovery_method=", "2");
        replace_token_value(s, "phx_rus_conf.kernel_time=", "0");
        replace_token_value(s, "phx_rus_conf.android_time=", "0");
    }
}

static void sanitize_status(std::string& s) {
    size_t pos = 0;
    while ((pos = s.find("TracerPid:", pos)) != std::string::npos) {
        size_t e = s.find('\n', pos);
        if (e == std::string::npos) e = s.size();
        s.replace(pos, e - pos, "TracerPid:\t0");
        pos += 11;
    }
}

static bool build_fake_content(FakeKind kind, const char* path, std::string& out) {
    switch (kind) {
        case FK_SOC_SERIAL:
            if (!g_fake_soc[0]) return false;
            out.assign(g_fake_soc);
            out.push_back('\n');
            return true;

        case FK_MAPS:
        case FK_SMAPS: {
            // 实验开关：默认关闭行过滤。
            // 理由：SUSFS 的 add_sus_map 已在内核层让模块 apk 路径"不存在"，
            // 而 libc 层再删行会造成 maps 行数与 ART 自身认知不一致 —— 这种
            // 不一致本身可能正是 fekit dlvm 判定的依据。
            if (g_nofilter_maps) return false;
            std::string real;
            if (!read_real_file(path, real)) {
                LOGI("read_real_file failed: %s", path);
                return false;
            }
            out = filter_lines(real);
            LOGI("filtered %s: %zu -> %zu bytes", path, real.size(), out.size());
            return true;
        }

        case FK_MOUNTINFO: {
            std::string real;
            if (!read_real_file(path, real)) {
                LOGI("read_real_file failed: %s", path);
                return false;
            }
            out = filter_lines(real);
            LOGI("filtered %s: %zu -> %zu bytes", path, real.size(), out.size());
            return true;
        }

        // /proc/net/unix 与 mounts 同样按行过滤：kBlacklist 里的 "lspd" 会命中
        // LSPosed daemon 的抽象 socket 行（形如 "... 1234 /lspd"）。
        // 只删 socket 名行，保留表头与其余条目，避免行数/格式异常。
        case FK_NET_UNIX: {
            std::string real;
            if (!read_real_file(path, real)) {
                // 关键判定：本机 untrusted_app 域对 /proc/net 是否有读权限。
                // 失败 = fekit 那次 fopen 同样拿不到内容，/lspd 不构成泄漏。
                LOGI("net/unix unreadable in-app (errno=%d): %s", errno, path);
                return false;
            }
            out = filter_lines(real);
            LOGI("filtered %s: %zu -> %zu bytes", path, real.size(), out.size());
            return true;
        }

        case FK_PROC_CMDLINE: {
            // 【V9 最简方案】读其他进程的 cmdline 时，若进程名是 root 框架，
            // 返回空内容（QQ 看到空 = 该进程名不可见）。
            // 不做复杂伪造：普通进程原样返回，只有 root 进程被抹掉。
            std::string real;
            if (!read_real_file(path, real)) return false;

            // cmdline 是 NUL 分隔的，取第一段作为进程名
            size_t nul = real.find('\0');
            std::string name = (nul == std::string::npos) ? real : real.substr(0, nul);

            if (is_root_process_name(name.c_str())) {
                LOGI("PROC-CMDLINE hidden: %s -> [%s]", path, name.c_str());
                out.clear();   // 返回空
                return true;
            }
            return false;      // 非 root 进程：走原始路径，零开销
        }

        case FK_STATUS: {
            std::string real;
            if (!read_real_file(path, real)) return false;
            sanitize_status(real);
            out = std::move(real);
            return true;
        }

        case FK_BOOTCONFIG: {
            std::string real;
            if (!read_real_file(path, real)) return false;
            sanitize_cmdline(real);  // 同样的键值对格式
            out = std::move(real);
            return true;
        }

        case FK_CPUINFO: {
            // 【V7】/proc/cpuinfo 的 Hardware 行暴露真机 SoC（SM8350）。
            // OPPO Find X7 = 骁龙 8 Gen 3 (SM8650)，必须同步。
            std::string real;
            if (!read_real_file(path, real)) return false;
            out.clear();
            size_t pos = 0;
            while (pos < real.size()) {
                size_t nl = real.find('\n', pos);
                if (nl == std::string::npos) nl = real.size();
                std::string line = real.substr(pos, nl - pos);
                if (line.rfind("Hardware", 0) == 0) {
                    out += "Hardware\t: Qualcomm Technologies, Inc SM8650";
                } else if (line.rfind("Processor", 0) == 0 ||
                           line.rfind("model name", 0) == 0) {
                    out += "Processor\t: AArch64 Processor rev 14 (aarch64)";
                } else if (line.rfind("CPU part", 0) == 0) {
                    out += "CPU part\t: 0xd4d";   // Cortex-X4
                } else {
                    out += line;
                }
                out += "\n";
                pos = nl + 1;
            }
            return true;
        }

        case FK_VERSION: {
            if (!g_env_on) return false;
            out = "Linux version ";
            out += g_env[12];
            out += " (build@build) (Android clang version 14.0.7) ";
            out += g_env[13];
            out += "\n";
            return true;
        }

        case FK_CMDLINE: {
            std::string real;
            if (!read_real_file(path, real)) return false;
            sanitize_cmdline(real);
            out = std::move(real);
            return true;
        }

        default:
            return false;
    }
}

// 生成一个只读 fd，内容为 content（memfd 失败时回退 tmpfile）
static int make_fake_fd(const std::string& content) {
    int fd = -1;
#ifdef __NR_memfd_create
    fd = (int)syscall(__NR_memfd_create, "jit-cache", 1 /* MFD_CLOEXEC */);
#endif
    if (fd >= 0) {
        const char* p = content.data();
        size_t left = content.size();
        while (left > 0) {
            ssize_t n = (ssize_t)syscall(__NR_write, fd, p, left);
            if (n <= 0) {
                syscall(__NR_close, fd);
                return -1;
            }
            p += n;
            left -= (size_t)n;
        }
    } else {
        FILE* f = tmpfile();
        if (!f) return -1;
        if (!content.empty()) fwrite(content.data(), 1, content.size(), f);
        fflush(f);
        fd = dup(fileno(f));
        fclose(f);
    }
    if (fd < 0) return -1;
    lseek(fd, 0, SEEK_SET);
    return fd;
}

static FILE* make_fake_file(const std::string& content) {
    int fd = make_fake_fd(content);
    if (fd < 0) return nullptr;
    FILE* f = fdopen(fd, "r");
    if (!f) {
        syscall(__NR_close, fd);
        return nullptr;
    }
    return f;
}

//  path 需要伪造且可读，返 fd；否 -1
static int try_fake_open(const char* fn, const char* path, int flags, void* ra) {
    if (!path) return -1;
    // 写模式盲区修复：之前只对 O_RDONLY 记日志，导致 .android_lq 的写 open
    // 从未被观测到。这里对含 .android_lq 的路径无论读写都记录（定位写入者）。
    if (strstr(path, ".android_lq")) {
        LOGI("OPEN .android_lq %s ra=%p flags=0x%x path=%.140s",
             fn, ra, (unsigned) flags, path);
        // ===== P2 注入：.android_lq 任何模式都返回受控 memfd =====
        // fekit 读 → 我们的伪造值；fe kit 写 → 进 memfd 无副作用。
        // 有效值完全受控 = 新设备锚。
        std::string fake_lq;
        if (get_fake_lq(fake_lq)) {
            int lq_fd = make_fake_fd(fake_lq);
            if (lq_fd >= 0) {
                LOGI("FAKE .android_lq: serving %zu bytes", fake_lq.size());
                t_lq_write_fd = -1;  // 不跟踪（memfd 无需写观测）
                return lq_fd;
            }
        }
    }
    if ((flags & O_ACCMODE) != O_RDONLY) return -1;

    probe_log_path(path);

    FakeKind kind = classify_path(path);
    if (kind == FK_NONE) {
        attr_report(fn, path, "pass", ra);
        return -1;
    }

    std::string content;
    if (!build_fake_content(kind, path, content)) {
        attr_report(fn, path, "pass", ra);
        return -1;
    }

    int fd = make_fake_fd(content);
    if (fd >= 0) {
        log_faked_once("read", path);
        attr_report(fn, path, "fake", ra);
    } else {
        LOGI("make_fake_fd failed for %s (content %zu bytes)", path, content.size());
        attr_report(fn, path, "fail", ra);
    }
    return fd;
}

static FILE* try_fake_fopen(const char* fn, const char* path, const char* mode, void* ra) {
    if (!path || !mode || mode[0] != 'r') return nullptr;

    probe_log_path(path);

    FakeKind kind = classify_path(path);
    if (kind == FK_NONE) {
        attr_report(fn, path, "pass", ra);
        return nullptr;
    }

    std::string content;
    if (!build_fake_content(kind, path, content)) {
        attr_report(fn, path, "pass", ra);
        return nullptr;
    }

    FILE* f = make_fake_file(content);
    if (f) {
        log_faked_once("fopen", path);
        attr_report(fn, path, "fake", ra);
    } else {
        attr_report(fn, path, "fail", ra);
    }
    return f;
}

// ---------------------------------------------------------------------------
// fopen / fopen64
// ---------------------------------------------------------------------------

// 取本 hook 的调用者返回地址。必须在函数第一句调用：LR 尚未被 prologue 覆盖。
#define HOOK_RA() ((void*) __builtin_extract_return_addr(__builtin_return_address(0)))

static FILE* fake_fopen(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    FILE* f = try_fake_fopen("fopen", path, mode, ra);
    if (f) return f;
    return BYTEHOOK_CALL_PREV(fake_fopen, path, mode);
}

static FILE* fake_fopen64(const char* path, const char* mode) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    FILE* f = try_fake_fopen("fopen64", path, mode, ra);
    if (f) return f;
    return BYTEHOOK_CALL_PREV(fake_fopen64, path, mode);
}

// fgets 代理：兜底伪造 TracerPid（fopen 已被拦截时一般用不到）
// prctl(PR_SET_DUMPABLE, 0) 会让进程从内核层面拒绝 ptrace 附加 —— 这是 QQ 反调试
// 的底层手段，Java 层的 TracerPid 伪装绕不过它。这里把该调用变成空操作。
static int fake_prctl(int option, unsigned long arg2, unsigned long arg3,
                      unsigned long arg4, unsigned long arg5) {
    BYTEHOOK_STACK_SCOPE();
#ifdef PR_SET_DUMPABLE
    if (option == PR_SET_DUMPABLE && arg2 == 0) {
        LOGI("blocked prctl(PR_SET_DUMPABLE, 0)");
        return 0;
    }
#endif
    return BYTEHOOK_CALL_PREV(fake_prctl, option, arg2, arg3, arg4, arg5);
}

static char* fake_fgets(char* s, int size, FILE* stream) {
    BYTEHOOK_STACK_SCOPE();
    char* result = BYTEHOOK_CALL_PREV(fake_fgets, s, size, stream);
    if (result && s && size > 12 && strncmp(s, "TracerPid:", 10) == 0) {
        snprintf(s, (size_t)size, "TracerPid:\t0\n");
    }
    return result;
}

// ---------------------------------------------------------------------------
// open / open64 / openat / openat64 / __open_2 / __openat_2
// ---------------------------------------------------------------------------

static int fake_open(const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int fd = try_fake_open("open", pathname, flags, ra);
    if (fd >= 0) return fd;
    fd = BYTEHOOK_CALL_PREV(fake_open, pathname, flags, mode);
    if (fd >= 0 && pathname && strstr(pathname, ".android_lq")) t_lq_write_fd = fd;
    return fd;
}

static int fake_open64(const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    int fd = try_fake_open("open64", pathname, flags, ra);
    if (fd >= 0) return fd;
    fd = BYTEHOOK_CALL_PREV(fake_open64, pathname, flags, mode);
    if (fd >= 0 && pathname && strstr(pathname, ".android_lq")) t_lq_write_fd = fd;
    return fd;
}

static int fake_openat(int dirfd, const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (pathname && pathname[0] == '/') {
        int fd = try_fake_open("openat", pathname, flags, ra);
        if (fd >= 0) return fd;
    }
    int fd = BYTEHOOK_CALL_PREV(fake_openat, dirfd, pathname, flags, mode);
    if (fd >= 0 && pathname && strstr(pathname, ".android_lq")) t_lq_write_fd = fd;
    return fd;
}

static int fake_openat64(int dirfd, const char* pathname, int flags, ...) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list ap;
        va_start(ap, flags);
        mode = (mode_t)va_arg(ap, int);
        va_end(ap);
    }
    if (pathname && pathname[0] == '/') {
        int fd = try_fake_open("openat64", pathname, flags, ra);
        if (fd >= 0) return fd;
    }
    int fd = BYTEHOOK_CALL_PREV(fake_openat64, dirfd, pathname, flags, mode);
    if (fd >= 0 && pathname && strstr(pathname, ".android_lq")) t_lq_write_fd = fd;
    return fd;
}

static int fake_open_2(const char* pathname, int flags) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    int fd = try_fake_open("__open_2", pathname, flags, ra);
    if (fd >= 0) return fd;
    fd = BYTEHOOK_CALL_PREV(fake_open_2, pathname, flags);
    if (fd >= 0 && pathname && strstr(pathname, ".android_lq")) t_lq_write_fd = fd;
    return fd;
}

static int fake_openat_2(int dirfd, const char* pathname, int flags) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    if (pathname && pathname[0] == '/') {
        int fd = try_fake_open("__openat_2", pathname, flags, ra);
        if (fd >= 0) return fd;
    }
    int fd = BYTEHOOK_CALL_PREV(fake_openat_2, dirfd, pathname, flags);
    if (fd >= 0 && pathname && strstr(pathname, ".android_lq")) t_lq_write_fd = fd;
    return fd;
}

// ---------------------------------------------------------------------------
// readlink：隐 /proc/self/exe
// ---------------------------------------------------------------------------

static ssize_t fake_readlink(const char* path, char* buf, size_t bufsiz) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();

    if (path && strcmp(path, "/proc/self/exe") == 0) {
        const char* fake_path = "/system/bin/app_process64";
        size_t len = strlen(fake_path);
        if (len > bufsiz) len = bufsiz;
        memcpy(buf, fake_path, len);
        attr_report("readlink", path, "fake", ra);
        return (ssize_t)len;
    }
    attr_report("readlink", path, "pass", ra);
    return BYTEHOOK_CALL_PREV(fake_readlink, path, buf, bufsiz);
}

// ---------------------------------------------------------------------------
// access / stat / lstat / fstatat：隐藏敏感路 // ---------------------------------------------------------------------------

static bool is_hidden_path(const char* p) {
    if (!p) return false;
    static const char* hidden[] = {
        "/data/adb", "magisk", "kernelsu", "lsposed", "xposed", "frida",
        "/system/bin/su", "/system/xbin/su", "/sbin/su", "superuser",
        "busybox", "apatch", "/data/local/tmp/lsp", "/data/local/tmp/frida",
        "re.frida.server", "/system/xposed", nullptr
    };
    for (int i = 0; hidden[i]; i++) {
        if (strstr(p, hidden[i])) return true;
    }
    return false;
}

// 【V8 补全】进程列表过滤：QQ 可扫 /proc/<pid>/cmdline 看到 root 管理进程。
// 通过 open/openat 打开 /proc/<pid>/cmdline 时，记下 fd；read/fgets 时返回伪造内容。


static int fake_access(const char* pathname, int mode) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();

    if (is_hidden_path(pathname)) {
        probe_log_path(pathname);
        attr_report("access", pathname, "deny", ra);
        errno = ENOENT;
        return -1;
    }
    attr_report("access", pathname, "pass", ra);
    return BYTEHOOK_CALL_PREV(fake_access, pathname, mode);
}

static int fake_stat(const char* pathname, struct stat* st) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    if (is_hidden_path(pathname)) {
        probe_log_path(pathname);
        attr_report("stat", pathname, "deny", ra);
        errno = ENOENT;
        return -1;
    }
    attr_report("stat", pathname, "pass", ra);
    return BYTEHOOK_CALL_PREV(fake_stat, pathname, st);
}

static int fake_lstat(const char* pathname, struct stat* st) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    if (is_hidden_path(pathname)) {
        probe_log_path(pathname);
        attr_report("lstat", pathname, "deny", ra);
        errno = ENOENT;
        return -1;
    }
    attr_report("lstat", pathname, "pass", ra);
    return BYTEHOOK_CALL_PREV(fake_lstat, pathname, st);
}

static int fake_fstatat(int dirfd, const char* pathname, struct stat* st, int flags) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();
    if (is_hidden_path(pathname)) {
        probe_log_path(pathname);
        attr_report("fstatat", pathname, "deny", ra);
        errno = ENOENT;
        return -1;
    }
    attr_report("fstatat", pathname, "pass", ra);
    return BYTEHOOK_CALL_PREV(fake_fstatat, dirfd, pathname, st, flags);
}

// ---------------------------------------------------------------------------
// 系统属性：__system_property_get / __system_property_read_callback
// ---------------------------------------------------------------------------

static thread_local bool t_in_prop = false;

static bool is_probe_prop(const char* name) {
    if (!name) return false;
    static const char* kw[] = {
        "serial", "verifiedboot", "warranty", "flash.locked", "vbmeta",
        "debuggable", "qemu", "bootloader", "boot.hardware", "build.tags",
        "selinux", "soc", "imei", "android_id", "qimei", "boot.verified",
        "ro.secure", "ro.build.", "ro.product.", "ro.system.", "ro.vendor.",
        "ro.odm.", "ro.boot.", "ro.board.", "ro.hardware", "ro.chipname",
        "ro.config.", "ro.oplus.", "ro.coloros.", "ro.oxygen.", nullptr
    };
    for (int i = 0; kw[i]; i++) {
        if (strstr(name, kw[i])) return true;
    }
    return false;
}

static const char* fake_prop_value(const char* name) {
    if (!name) return nullptr;

    if (g_env_on) {
        if (strcmp(name, "ro.build.version.release") == 0) return g_env[0];
        if (strcmp(name, "ro.build.version.sdk") == 0) return g_env[1];
        if (strcmp(name, "ro.build.id") == 0) return g_env[2];
        if (strcmp(name, "ro.build.display.id") == 0) return g_env[3];
        if (strcmp(name, "ro.build.fingerprint") == 0 ||
            strcmp(name, "ro.system.build.fingerprint") == 0 ||
            strcmp(name, "ro.system_ext.build.fingerprint") == 0 ||
            strcmp(name, "ro.vendor.build.fingerprint") == 0 ||
            strcmp(name, "ro.odm.build.fingerprint") == 0 ||
            strcmp(name, "ro.product.build.fingerprint") == 0 ||
            strcmp(name, "ro.bootimage.build.fingerprint") == 0) {
            return g_env[4];
        }
        if (strcmp(name, "ro.build.description") == 0) return g_env[5];
        if (strcmp(name, "ro.build.host") == 0) return g_env[6];
        if (strcmp(name, "ro.build.user") == 0) return g_env[7];
        if (strcmp(name, "ro.build.date") == 0) return g_env[8];
        if (strcmp(name, "ro.build.version.incremental") == 0) return g_env[9];
        if (strcmp(name, "ro.build.version.security_patch") == 0) return g_env[10];
        if (strcmp(name, "ro.build.version.opporom") == 0) return g_env[11];
        if (strcmp(name, "ro.build.version.codename") == 0) return "REL";
        if (strcmp(name, "ro.build.version.all_codenames") == 0) return "REL";
        if (strcmp(name, "ro.build.version.preview_sdk") == 0) return "0";
        if (strcmp(name, "ro.build.version.preview_sdk_int") == 0) return "0";

        // 机型画像
        if (strcmp(name, "ro.product.model") == 0 ||
            strcmp(name, "ro.product.vendor.model") == 0 ||
            strcmp(name, "ro.product.system.model") == 0 ||
            strcmp(name, "ro.product.odm.model") == 0 ||
            strcmp(name, "ro.product.product.model") == 0) {
            return g_env[14];
        }
        if (strcmp(name, "ro.product.name") == 0 ||
            strcmp(name, "ro.product.vendor.name") == 0 ||
            strcmp(name, "ro.product.system.name") == 0 ||
            strcmp(name, "ro.product.odm.name") == 0 ||
            strcmp(name, "ro.product.product.name") == 0) {
            return g_env[15];
        }
        if (strcmp(name, "ro.product.device") == 0 ||
            strcmp(name, "ro.product.vendor.device") == 0 ||
            strcmp(name, "ro.product.system.device") == 0 ||
            strcmp(name, "ro.product.odm.device") == 0 ||
            strcmp(name, "ro.product.product.device") == 0 ||
            strcmp(name, "ro.build.product") == 0) {
            return g_env[16];
        }
        if (strcmp(name, "ro.product.brand") == 0 ||
            strcmp(name, "ro.product.vendor.brand") == 0 ||
            strcmp(name, "ro.product.system.brand") == 0) {
            return g_env[17];
        }
        if (strcmp(name, "ro.product.manufacturer") == 0 ||
            strcmp(name, "ro.product.vendor.manufacturer") == 0 ||
            strcmp(name, "ro.product.system.manufacturer") == 0) {
            return g_env[18];
        }
    }

    if (g_rom_host[0] && strcmp(name, "ro.build.host") == 0) return g_rom_host;
    if (g_rom_user[0] && strcmp(name, "ro.build.user") == 0) return g_rom_user;
    if (g_rom_display[0] && strcmp(name, "ro.build.display.id") == 0) return g_rom_display;
    if (g_rom_fingerprint[0]) {
        if (strcmp(name, "ro.build.fingerprint") == 0 ||
            strcmp(name, "ro.system.build.fingerprint") == 0 ||
            strcmp(name, "ro.system_ext.build.fingerprint") == 0 ||
            strcmp(name, "ro.vendor.build.fingerprint") == 0 ||
            strcmp(name, "ro.odm.build.fingerprint") == 0 ||
            strcmp(name, "ro.product.build.fingerprint") == 0 ||
            strcmp(name, "ro.bootimage.build.fingerprint") == 0) {
            return g_rom_fingerprint;
        }
    }

    if (g_boot_state[0] && strcmp(name, "ro.boot.verifiedbootstate") == 0) {
        return g_boot_state;
    }
    if (g_fake_serial[0]) {
        if (strcmp(name, "ro.serialno") == 0 ||
            strcmp(name, "ro.boot.serialno") == 0 ||
            strcmp(name, "ro.vendor.oplus.radio.serialno") == 0 ||
            strcmp(name, "vendor.oplus.caihong.serialno") == 0 ||
            strcmp(name, "persist.sys.oplus.serialno") == 0) {
            return g_fake_serial;
        }
    }
    if (strcmp(name, "ro.boot.flash.locked") == 0) return "1";
    if (strcmp(name, "ro.boot.vbmeta.device_state") == 0) return "locked";
    if (strcmp(name, "ro.boot.veritymode") == 0) return "enforcing";
    if (strcmp(name, "ro.boot.warranty_bit") == 0) return "0";
    if (strcmp(name, "ro.warranty_bit") == 0) return "0";
    if (strcmp(name, "ro.vendor.warranty_bit") == 0) return "0";
    if (strcmp(name, "ro.vendor.boot.warranty_bit") == 0) return "0";
    if (strcmp(name, "ro.boot.selinux") == 0) return "enforcing";
    // 【V7 修复】SoC / 平台标识 —— OPPO Find X7 = 骁龙 8 Gen 3 (SM8650)
    // 真机是 lahaina (SM8350/骁龙888)，必须同步换，否则 k54 与 k57(PGT110) 矛盾
    // 【V9 关键修复】QsecEst 的 k54 来自 ro.product.board，不是 ro.board.platform。
    // 之前只覆盖后者，导致 k54 一直报真机 "lahaina"，与伪造机型 PGT110 矛盾。
    // 这两个是不同的属性，必须都覆盖。
    if (strcmp(name, "ro.product.board") == 0 ||
        strcmp(name, "ro.product.vendor.board") == 0 ||
        strcmp(name, "ro.product.system.board") == 0 ||
        strcmp(name, "ro.product.odm.board") == 0 ||
        strcmp(name, "ro.product.product.board") == 0 ||
        strcmp(name, "ro.board.platform") == 0 ||
        strcmp(name, "ro.chipname") == 0 ||
        strcmp(name, "ro.hardware.chipname") == 0) {
        return "kalama";
    }
    if (strcmp(name, "ro.soc.model") == 0) return "SM8650";
    if (strcmp(name, "ro.soc.manufacturer") == 0) return "Qualcomm";
    if (strcmp(name, "ro.soc.platform") == 0) return "kalama";

    if (strcmp(name, "ro.debuggable") == 0) return "0";
    if (strcmp(name, "ro.secure") == 0) return "1";
    if (strcmp(name, "ro.kernel.qemu") == 0) return "";
    return nullptr;
}

static int fake___system_property_get(const char* name, char* value) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = HOOK_RA();

    if (t_in_prop || !name) {
        return BYTEHOOK_CALL_PREV(fake___system_property_get, name, value);
    }
    t_in_prop = true;

    int r = BYTEHOOK_CALL_PREV(fake___system_property_get, name, value);
    if (g_probe && is_probe_prop(name)) {
        LOGI("PROBE prop: %s = %.64s", name, value ? value : "");
    }
    const char* fake = fake_prop_value(name);
    if (fake && value) {
        // 不能用 strncpy(..., 91)：调用方经常给短属性（如 ro.build.version.sdk）
        // 只分配 3-4 字节的栈 buffer，strncpy 的 NUL 填充会直接踩坏栈。
        size_t flen = strlen(fake);
        if (flen > 91) flen = 91;
        memcpy(value, fake, flen);
        value[flen] = 0;
        r = (int)flen;
    }
    attr_report("prop", name, fake ? "fake" : "real", ra);
    t_in_prop = false;
    return r;
}

typedef void (*PropCallback)(void* cookie, const char* name, const char* value, uint32_t serial);

static thread_local PropCallback t_user_cb = nullptr;
static thread_local void* t_user_cookie = nullptr;

static void prop_trampoline(void* cookie, const char* name, const char* value, uint32_t serial) {
    (void)cookie;
    if (!t_user_cb) return;
    const char* fake = fake_prop_value(name);
    t_user_cb(t_user_cookie, name, fake ? fake : value, serial);
}

static void fake___system_property_read_callback(
    const void* pi, void (*callback)(void*, const char*, const char*, uint32_t), void* cookie) {
    BYTEHOOK_STACK_SCOPE();

    if (t_in_prop || !callback) {
        BYTEHOOK_CALL_PREV(fake___system_property_read_callback, pi, callback, cookie);
        return;
    }
    t_in_prop = true;
    t_user_cb = callback;
    t_user_cookie = cookie;
    BYTEHOOK_CALL_PREV(fake___system_property_read_callback, pi, prop_trampoline, cookie);
    t_user_cb = nullptr;
    t_user_cookie = nullptr;
    t_in_prop = false;
}

// ---------------------------------------------------------------------------
// 【T22 修复】__system_property_find：PCDN/部分 SDK 用 find + read_callback，
// find 返回 prop_info 结构指针，若 find 未被 hook，read_callback 改值可能来不及。
// 做法：find 时记录查询到的属性名（线程局部），read_callback 里据此查表伪造。
// ---------------------------------------------------------------------------

static thread_local const void* t_find_pi = nullptr;
static thread_local char t_find_name[128] = {0};

static const char* prop_key_to_name(const void* pi) {
    // 通过 pi 反查属性名：__system_property_read_callback 回调里能拿到真实 name，
    // 这里用另一个办法：把 find 返回的 pi 记录在 TLS，与 read_callback 的 pi 匹配。
    if (pi == t_find_pi && t_find_name[0]) return t_find_name;
    return nullptr;
}

static const void* fake___system_property_find(const char* name) {
    BYTEHOOK_STACK_SCOPE();
    const void* r = BYTEHOOK_CALL_PREV(fake___system_property_find, name);
    if (name && r) {
        // 记录 pi -> name，供 read_callback 使用（只记录我们关心的 key，避免开销）
        if (fake_prop_value(name) != nullptr) {
            t_find_pi = r;
            strncpy(t_find_name, name, sizeof(t_find_name) - 1);
            t_find_name[sizeof(t_find_name) - 1] = 0;
        }
    }
    return r;
}

// uname 代理：把内核 release/version 伪装成官方风格
static int fake_uname(struct utsname* buf) {
    BYTEHOOK_STACK_SCOPE();
    int r = BYTEHOOK_CALL_PREV(fake_uname, buf);
    if (r == 0 && g_env_on && buf) {
        snprintf(buf->release, sizeof(buf->release), "%s", g_env[12]);
        snprintf(buf->version, sizeof(buf->version), "%s", g_env[13]);
    }
    return r;
}

// ---------------------------------------------------------------------------
// write 观测：抓 .android_lq 的写入内容（open 记录 fd → write 抓 buf）
// ---------------------------------------------------------------------------

static ssize_t fake_write(int fd, const void* buf, size_t count) {
    BYTEHOOK_STACK_SCOPE();
    if (t_lq_write_fd >= 0 && fd == t_lq_write_fd) {
        const unsigned char* p = (const unsigned char*) buf;
        size_t n = count < 128 ? count : 128;
        char hx[256 + 1];
        for (size_t i = 0; i < n; i++) {
            snprintf(hx + i * 2, 3, "%02x", p[i]);
        }
        LOGI("WRITE .android_lq fd=%d len=%zu data=%.256s", fd, count, hx);
        t_lq_write_fd = -1;
    }
    return BYTEHOOK_CALL_PREV(fake_write, fd, buf, count);
}

// ---------------------------------------------------------------------------
// 最小化 syscall 观测：定位 .android_lq 的写入函数
//
// fekit 只依赖 libc，直通 syscall 走 libc 的 syscall() 包装（导入 syscall@LIBC）。
// hook 它就能拦到写 .android_lq 的 openat/write，并拿到调用者 RA（= fekit 内部
// 函数偏移，可在 IDA 里定位计算函数）。
//
// 安全设计（前车之鉴：全量 syscall hook 在 pthread_exit 时 TLS 递归 SIGSEGV）：
//  - hook 体零 malloc / 零 C++ 分配，纯内存读 + 直通
//  - 只匹配 syscall 号 56(openat)/64(write)，且路径含 ".android_lq" 才打日志
//  - 不匹配路径时与原始实现等价（无额外开销）
//  - 日志用截断固定长度，避免长字符串处理
// ---------------------------------------------------------------------------

static thread_local int t_lq_fd = -1;

static bool lq_mem_contains(const char* p, size_t maxlen, const char* needle) {
    // 手写包含检查，避免调用 libc strstr（可能触发递归）
    if (!p || !needle) return false;
    size_t nl = 0;
    while (needle[nl]) nl++;
    if (nl == 0 || nl > maxlen) return false;
    for (size_t i = 0; i <= maxlen - nl; i++) {
        if (p[i] == 0) break;
        size_t j = 0;
        while (j < nl && p[i + j] == needle[j]) j++;
        if (j == nl) return true;
    }
    return false;
}

static long fake_syscall(long number, long a1, long a2, long a3,
                         long a4, long a5, long a6) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = __builtin_extract_return_addr(__builtin_return_address(0));

#if defined(__aarch64__)
    // arm64: __NR_openat=56, __NR_write=64
    if (number == 56) {
        const char* path = (const char*) a2;  // openat(dirfd, path, flags, mode)
        if (lq_mem_contains(path, 300, ".android_lq")) {
            LOGI("SYSCALL openat .android_lq ra=%p path=%.160s", ra, path ? path : "(null)");
            long r = BYTEHOOK_CALL_PREV(fake_syscall, number, a1, a2, a3, a4, a5, a6);
            if (r >= 0) t_lq_fd = (int) r;
            return r;
        }
    } else if (number == 64) {
        if (t_lq_fd >= 0 && a1 == (long) t_lq_fd) {
            const char* buf = (const char*) a2;
            LOGI("SYSCALL write .android_lq ra=%p len=%ld data=%.80s", ra, a3,
                 buf ? buf : "(null)");
            t_lq_fd = -1;
        }
    }
#else
    // armeabi-v7a: __NR_openat=322, __NR_write=4
    if (number == 322) {
        const char* path = (const char*) a2;
        if (lq_mem_contains(path, 300, ".android_lq")) {
            LOGI("SYSCALL openat .android_lq ra=%p path=%.160s", ra, path ? path : "(null)");
            long r = BYTEHOOK_CALL_PREV(fake_syscall, number, a1, a2, a3, a4, a5, a6);
            if (r >= 0) t_lq_fd = (int) r;
            return r;
        }
    } else if (number == 4) {
        if (t_lq_fd >= 0 && a1 == (long) t_lq_fd) {
            const char* buf = (const char*) a2;
            LOGI("SYSCALL write .android_lq ra=%p len=%ld data=%.80s", ra, a3,
                 buf ? buf : "(null)");
            t_lq_fd = -1;
        }
    }
#endif
    return BYTEHOOK_CALL_PREV(fake_syscall, number, a1, a2, a3, a4, a5, a6);
}

// ---------------------------------------------------------------------------
// DLVM 判定值正常化：把 fekit 写入的 "failed!" 改写为 "end"（正常）
//
// fekit DLVM 判定结果写 MMKV：dlvm_mmkv_key_2025082115 = "failed!"(异常)/"end"(正常)。
// ByteHook 是 PLT hook，hook 不到 fekit 内部函数 → 只能在 libc 层拦截 memcpy/strcpy。
// 当 src 是 "failed!" 常量时，拷贝后把 dst 前缀改写为 "end\0"。
// 安全：hook 体零 malloc/零 std::string；首字节 'f' 快速直通，命中才完整比较。
// ---------------------------------------------------------------------------

static inline bool dlvm_is_failed(const char* p) {
    // 手写 7 字节比较 "failed!"，零依赖（不调 libc memcmp，避免任何递归风险）
    return p && p[0] == 'f' && p[1] == 'a' && p[2] == 'i' && p[3] == 'l' &&
           p[4] == 'e' && p[5] == 'd' && p[6] == '!';
}

static inline void dlvm_rewrite_end(char* dst, size_t cap) {
    // 把 dst 前缀改写为 "end\0"（不越界，cap = 可用长度）
    if (cap >= 4) {
        dst[0] = 'e'; dst[1] = 'n'; dst[2] = 'd'; dst[3] = 0;
    } else if (cap >= 3) {
        dst[0] = 'e'; dst[1] = 'n'; dst[2] = 'd';
    } else if (cap >= 2) {
        dst[0] = 'e'; dst[1] = 'n';
    } else if (cap >= 1) {
        dst[0] = 'e';
    }
}

static uintptr_t g_tur_lo = 0, g_tur_hi = 0;
static int g_tur_resolves = 0;

static int find_tur_cb(struct dl_phdr_info* info, size_t sz, void* data) {
    (void) sz;
    (void) data;
    if (!info || !info->dlpi_name) return 0;
    if (!strstr(info->dlpi_name, "libturing")) return 0;
    uintptr_t lo = (uintptr_t) info->dlpi_addr;
    uintptr_t hi = lo;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        uintptr_t end = lo + ph->p_vaddr + ph->p_memsz;
        if (end > hi) hi = end;
    }
    g_tur_lo = lo;
    g_tur_hi = hi;
    return 1;
}

static void ensure_tur_range() {
    // 【已修 bug】旧版对解析次数设了硬上限 4 次：若前 4 次调用发生在 libturingxq
    // 尚未映射时，g_tur_lo 会永久停在 0 → caller_in_turing_libc() 恒 false →
    // TURING_PLAIN / TURING_KEYCAND 永久静默（表现为"hook 装了但一条都抓不到"）。
    // 改为未解析成功就每次重试；deflate/strncpy 调用频率极低，dl_iterate_phdr 代价可忽略。
    if (g_tur_lo == 0) {
        g_tur_resolves++;
        dl_iterate_phdr(find_tur_cb, nullptr);
        if (g_tur_lo == 0 && (g_tur_resolves % 200) == 1) {
            LOGI("turing range still unresolved (attempts=%d)", g_tur_resolves);
        }
    }
}

static bool caller_in_turing_libc(void* caller) {
    uintptr_t a = (uintptr_t) caller;
    return g_tur_lo != 0 && a >= g_tur_lo && a < g_tur_hi;
}

// 前置声明（定义在下方 libz 段）
static void dump_hex_file(const char* tag, const unsigned char* p, size_t n);
static void diag_caller(const char* who, void* ra);

static void* fake_memcpy(void* dst, const void* src, size_t n) {
    BYTEHOOK_STACK_SCOPE();
    const char* s = (const char*) src;
    if (n >= 7 && s && s[0] == 'f' && dlvm_is_failed(s)) {
        void* r = BYTEHOOK_CALL_PREV(fake_memcpy, dst, src, n);
        // 取证：完整 buffer + 调用者模块/偏移 → 定位 29 项里到底哪一项判 failed
        size_t kn = n > 64 ? 64 : n;
        char hx[129];
        for (size_t i = 0; i < kn; i++) {
            snprintf(hx + i * 2, 3, "%02x", (unsigned char) s[i]);
        }
        void* ra = __builtin_extract_return_addr(__builtin_return_address(0));
        Dl_info info;
        memset(&info, 0, sizeof(info));
        if (dladdr(ra, &info) && info.dli_fname) {
            LOGI("DLVM rewrite: memcpy failed! -> end (n=%zu) caller=%s+0x%zx hex=%.128s",
                 n, info.dli_fname, (size_t) ((uintptr_t) ra - (uintptr_t) info.dli_fbase), hx);
        } else {
            LOGI("DLVM rewrite: memcpy failed! -> end (n=%zu) caller=%p hex=%.128s", n, ra, hx);
        }
        dump_hex_file("DLVM_FAILED", (const unsigned char*) s, n);
        dlvm_rewrite_end((char*) dst, n);
        return r;
    }
    return BYTEHOOK_CALL_PREV(fake_memcpy, dst, src, n);
}

static char* fake_strcpy(char* dst, const char* src) {
    BYTEHOOK_STACK_SCOPE();
    if (src && src[0] == 'f' && dlvm_is_failed(src)) {
        char* r = BYTEHOOK_CALL_PREV(fake_strcpy, dst, src);
        dlvm_rewrite_end(dst, 4);
        LOGI("DLVM rewrite: strcpy failed! -> end");
        return r;
    }
    return BYTEHOOK_CALL_PREV(fake_strcpy, dst, src);
}

static char* fake_strncpy(char* dst, const char* src, size_t n) {
    BYTEHOOK_STACK_SCOPE();
    // XTEA 密钥抓取：libturingxq 从宿主接口取 16B 密钥时经 strncpy（sub_22CC0）
    void* ra = __builtin_extract_return_addr(__builtin_return_address(0));
    ensure_tur_range();
    if (src && n >= 16) {
        if (g_probe && n >= 32) diag_caller("strncpy", ra);
        if (caller_in_turing_libc(ra)) {
            size_t kn = n > 64 ? 64 : n;
            char hx[129];
            for (size_t i = 0; i < kn; i++) {
                snprintf(hx + i * 2, 3, "%02x", (unsigned char) src[i]);
            }
            LOGI("TURING_KEYCAND strncpy n=%zu key64=%.128s", n, hx);
            dump_hex_file("TURING_KEYCAND", (const unsigned char*) src, n);
        }
    }
    if (n >= 4 && src && src[0] == 'f' && dlvm_is_failed(src)) {
        char* r = BYTEHOOK_CALL_PREV(fake_strncpy, dst, src, n);
        dlvm_rewrite_end(dst, n);
        LOGI("DLVM rewrite: strncpy failed! -> end (n=%zu)", n);
        return r;
    }
    return BYTEHOOK_CALL_PREV(fake_strncpy, dst, src, n);
}

// ---------------------------------------------------------------------------
// libz deflate 明文抓取：Turing 加密上报前经 zlib 压缩，hook deflate 拿明文
// ---------------------------------------------------------------------------

// z_stream 关键字段（避免引入 zlib.h 依赖，NDK sysroot 有 zlib.h 但保险起见手写）
struct LzStream {
    const unsigned char* next_in;
    unsigned int avail_in;
    unsigned long long total_in;
    unsigned char* next_out;
    unsigned int avail_out;
    unsigned long long total_out;
};



// ---------------------------------------------------------------------------
// 明文/密钥落盘：logcat 缓冲只有 1MB 且按 tag 轮转，登录窗口的明文极易被冲掉。
// 这里直接用 syscall 追加写文件（不经我们自己的 open/write hook），
// 供离线精确分析；logcat 只保留长度 + 前 64B 摘要。
// ---------------------------------------------------------------------------

#define DUMP_PATH "/storage/emulated/0/Android/data/com.tencent.mobileqq/turing_dump.log"
#define DUMP_MAX_BYTES 4096

static void dump_hex_file(const char* tag, const unsigned char* p, size_t n) {
    if (!p || n == 0) return;
    size_t max = n > DUMP_MAX_BYTES ? DUMP_MAX_BYTES : n;
    static const char hxd[] = "0123456789abcdef";
    char line[DUMP_MAX_BYTES * 2 + 96];
    int len = snprintf(line, sizeof(line), "%ld %s len=%zu hex=", (long) time(nullptr), tag, n);
    if (len < 0) return;
    for (size_t i = 0; i < max; i++) {
        if (len + 4 >= (int) sizeof(line)) break;
        line[len++] = hxd[(p[i] >> 4) & 0xf];
        line[len++] = hxd[p[i] & 0xf];
    }
    line[len++] = '\n';
    int fd = (int) syscall(SYS_openat, AT_FDCWD, DUMP_PATH,
                           O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return;
    syscall(SYS_write, fd, line, (size_t) len);
    syscall(SYS_close, fd);
}

// 调用者归因：把 deflate/strncpy 见到的每个不同返回地址解析成 "模块+偏移"，
// 用于确认 libturingxq 到底走的是 libz 导出还是内嵌副本。每地址只打一次。
static uintptr_t g_diag_ra[24];
static int g_diag_n = 0;

static void diag_caller(const char* who, void* ra) {
    uintptr_t a = (uintptr_t) ra;
    for (int i = 0; i < g_diag_n; i++) {
        if (g_diag_ra[i] == a) return;
    }
    if (g_diag_n >= 24) return;
    g_diag_ra[g_diag_n++] = a;
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr(ra, &info) && info.dli_fname) {
        LOGI("CALLER %s ra=%p mod=%s off=0x%zx", who, ra, info.dli_fname,
             (size_t) (a - (uintptr_t) info.dli_fbase));
    } else {
        LOGI("CALLER %s ra=%p mod=(unknown)", who, ra);
    }
}

// ---------------------------------------------------------------------------
// 上游注入：在 deflate 压缩前改写明文（异常值 → 正常值）
// 规则从 /storage/emulated/0/Android/data/com.tencent.mobileqq/inject.txt 读取，
// 每行 "FROM_HEX=TO_HEX"（等长替换，原地改副本）。文件不存在则不动明文。
// 拿到字段后只需改文本文件 + 重启 QQ，不必重新编译。
// ---------------------------------------------------------------------------

#define INJECT_RULES_PATH "/storage/emulated/0/Android/data/com.tencent.mobileqq/inject.txt"
#define INJECT_BUF_MAX 8192
#define INJECT_MAX_RULES 8

struct InjectRule {
    unsigned char from[128];
    unsigned char to[128];
    int len;
    int used;
};

static InjectRule g_rules[INJECT_MAX_RULES];
static int g_rule_n = 0;
static int g_rule_loaded = 0;
static unsigned char g_inject_buf[INJECT_BUF_MAX];

static int hex_nibble(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char* s, int s_len, unsigned char* out, int out_cap) {
    int n = 0;
    for (int i = 0; i + 1 < s_len && n < out_cap; i += 2) {
        int h = hex_nibble(s[i]);
        int l = hex_nibble(s[i + 1]);
        if (h < 0 || l < 0) break;
        out[n++] = (unsigned char) ((h << 4) | l);
    }
    return n;
}

static void load_inject_rules() {
    if (g_rule_loaded) return;
    g_rule_loaded = 1;
    int fd = (int) syscall(SYS_openat, AT_FDCWD, INJECT_RULES_PATH, O_RDONLY, 0);
    if (fd < 0) return;
    char buf[2048];
    long r = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
    syscall(SYS_close, fd);
    if (r <= 0) return;
    buf[r] = 0;
    int i = 0;
    while (i < (int) r && g_rule_n < INJECT_MAX_RULES) {
        int line_start = i;
        while (i < (int) r && buf[i] != '\n' && buf[i] != '\r') i++;
        int line_end = i;
        while (i < (int) r && (buf[i] == '\n' || buf[i] == '\r')) i++;
        if (line_end - line_start < 3) continue;
        if (buf[line_start] == '#') continue;
        int eq = -1;
        for (int k = line_start; k < line_end; k++) {
            if (buf[k] == '=') { eq = k; break; }
        }
        if (eq < 0) continue;
        int fl = eq - line_start;
        int tl = line_end - eq - 1;
        int fn = hex_decode(buf + line_start, fl, g_rules[g_rule_n].from, 128);
        int tn = hex_decode(buf + eq + 1, tl, g_rules[g_rule_n].to, 128);
        if (fn > 0 && fn == tn) {
            g_rules[g_rule_n].len = fn;
            g_rules[g_rule_n].used = 0;
            g_rule_n++;
        }
    }
    LOGI("INJECT rules loaded: %d", g_rule_n);
}

/** 对 buf 应用全部规则，返回命中的规则数 */
static int inject_apply(unsigned char* buf, size_t n) {
    int hits = 0;
    for (int r = 0; r < g_rule_n; r++) {
        int len = g_rules[r].len;
        if (len <= 0 || (size_t) len > n) continue;
        for (size_t off = 0; off + (size_t) len <= n; off++) {
            if (memcmp(buf + off, g_rules[r].from, (size_t) len) != 0) continue;
            memcpy(buf + off, g_rules[r].to, (size_t) len);
            hits++;
            g_rules[r].used++;
            LOGI("INJECT hit rule=%d off=%zu len=%d", r, off, len);
        }
    }
    return hits;
}

static int fake_deflate(LzStream* strm, int flush) {
    BYTEHOOK_STACK_SCOPE();
    void* ra = __builtin_extract_return_addr(__builtin_return_address(0));
    ensure_tur_range();
    const unsigned char* orig_in = nullptr;
    bool swapped = false;

    if (strm && strm->next_in && strm->avail_in > 0) {
        load_inject_rules();
        if (caller_in_turing_libc(ra)) {
            // 全量落盘（最多 4096B），logcat 只留摘要
            dump_hex_file("TURING_PLAIN", strm->next_in, strm->avail_in);
            size_t n = strm->avail_in < 64 ? strm->avail_in : 64;
            char hx[129];
            for (size_t i = 0; i < n; i++) {
                snprintf(hx + i * 2, 3, "%02x", strm->next_in[i]);
            }
            LOGI("TURING_PLAIN len=%u hex64=%.128s", strm->avail_in, hx);

            // 上游注入：改副本再压缩，服务端收到的是正常值
            if (g_rule_n > 0 && strm->avail_in <= INJECT_BUF_MAX) {
                size_t in_len = strm->avail_in;
                memcpy(g_inject_buf, strm->next_in, in_len);
                if (inject_apply(g_inject_buf, in_len) > 0) {
                    dump_hex_file("TURING_INJECTED", g_inject_buf, in_len);
                    orig_in = strm->next_in;
                    strm->next_in = g_inject_buf;
                    swapped = true;
                }
            }
        }
    }
    int rc = BYTEHOOK_CALL_PREV(fake_deflate, strm, flush);
    if (swapped) strm->next_in = orig_in;
    return rc;
}

// ---------------------------------------------------------------------------
// DLVM 治本注入：hook libmmkv 导出符号 MMKV::set(string,string)（0x3f8a0）
// fekit 判定链 sub_129AF0 → sub_34EBFC!=0 → "failed!" → sub_31FB54 →
// qword_748B20(MMKKV实例) vtable+48 → 实际落点就是 libmmkv 的 MMKV::set。
// 符号级 hook 稳定不依赖 fekit 混淆偏移；只拦 dlvm_mmkv key，其他 kv 不碰。
// ---------------------------------------------------------------------------

static const char* DLVM_KEY = "dlvm_mmkv_key_2025082115";

typedef void (*MMKVSet_str_fn)(void* thiz, void* key, void* value);

static bool is_dlvm_key(const void* key) {
    // std::string（libc++ _ndk1）SSO 布局：短串 {char buf[23]; uint8 size}，
    // 长串 {char* ptr; size_t size; size_t cap|1}。先按短串读，>22B 按长串。
    if (!key) return false;
    const unsigned char* k = (const unsigned char*) key;
    size_t len = 0;
    const char* data = nullptr;
    unsigned char last = k[23];
    if (last <= 22) {           // SSO 短串（size 存最高字节，& 0x80 为长串标志）
        len = last;
        data = (const char*) k;
    } else {                    // 长串
        const char* const* p = (const char* const*) k;
        const size_t* sz = (const size_t*) (k + 8);
        data = *p;
        len = *sz;
    }
    if (len < 6 || !data) return false;
    // T6 核对：实例A key=dlvm_mmkv_key_2025082115（value=failed!/end，7B）
    //          实例B key=dlvm_mmkv_report_2025082115（value=failed!+8B 打包）
    //          vm_result 键（sub_129DB0）value="failed"(6B)/"end"
    if (memcmp(data, "dlvm_mmkv_", 10) == 0) return true;   // 覆盖 key_/report_ 两个实例
    if (memcmp(data, "vm_result", 9) == 0) return true;
    return false;
}

/** 读 libc++ string 内容（SSO 双读），返回 data/len；无效返回 false */
static bool cpp_str_read(const void* s, const char** out_data, size_t* out_len) {
    if (!s) return false;
    const unsigned char* k = (const unsigned char*) s;
    unsigned char last = k[23];
    if (last <= 22) {
        *out_data = (const char*) k;
        *out_len = last;
        return true;
    }
    const char* const* p = (const char* const*) k;
    const size_t* sz = (const size_t*) (k + 8);
    if (!*p || *sz == 0 || *sz > 1 << 20) return false;
    *out_data = *p;
    *out_len = *sz;
    return true;
}

/** 把 value 前缀 failed!/failed 改写为 end（SSO 就地），返回是否命中 */
static bool dlvm_rewrite_value(void* value) {
    const char* d;
    size_t n;
    if (!cpp_str_read(value, &d, &n)) return false;
    bool hit = false;
    if (n >= 7 && memcmp(d, "failed!", 7) == 0) hit = true;
    else if (n >= 6 && memcmp(d, "failed", 6) == 0) hit = true;
    if (!hit) return false;
    unsigned char* v = (unsigned char*) value;
    unsigned char vlast = v[23];
    if (vlast <= 22) {
        // SSO 短串：就地改写
        v[0] = 'e'; v[1] = 'n'; v[2] = 'd';
        unsigned char newsz = (vlast == 7) ? 3 : (vlast == 6 ? 3 : vlast);
        // "failed!"(7B)->"end"(3B)，"failed"(6B)->"end"(3B)；若 value 带 8B payload
        //（report 打包 15B），保留尾部只改头部 7B 为 "end"+8B payload 原样：
        if (vlast > 22) return false;   // 不会发生（防御）
        v[23] = 3;                      // size="end"
        memset((void*) (v + 3), 0, 19);
        dump_hex_file("DLVM_UPSTREAM", v, 3);
        return true;
    }
    // 长串：改写堆上内容前 7B
    char* heap = (char*) v;
    heap[0] = 'e'; heap[1] = 'n'; heap[2] = 'd';
    for (size_t i = 3; i < 7 && i < n; i++) heap[i] = 0;
    dump_hex_file("DLVM_UPSTREAM", (const unsigned char*) heap, 7);
    return true;
}

static void fake_mmkv_set_str(void* thiz, void* key, void* value) {
    BYTEHOOK_STACK_SCOPE();
    if (is_dlvm_key(key) && value) {
        const char* d;
        size_t n;
        if (cpp_str_read(value, &d, &n) && n > 0) {
            char hx[65];
            size_t kn = n > 32 ? 32 : n;
            for (size_t i = 0; i < kn; i++) {
                snprintf(hx + i * 2, 3, "%02x", (unsigned char) d[i]);
            }
            hx[kn * 2] = 0;
            LOGI("MMKV set dlvm: value[%zu]=%s", n, hx);
            if (dlvm_rewrite_value(value)) {
                LOGI("MMKV set: dlvm failed -> end (upstream root fix)");
            }
        }
    }
    BYTEHOOK_CALL_PREV(fake_mmkv_set_str, thiz, key, value);
}

// MMKV::set(MMBuffer, string) — 二进制值重载（T6 指出 dlvm report 可能走这里）
// MMKV::set(bool, string) — 布尔重载
static void* fake_mmkv_set_buf(void* thiz, void* buf, void* key) {
    BYTEHOOK_STACK_SCOPE();
    // 【T17 安全修正】MMBuffer 是值传递的类对象，布局未证实（可能是 {ptr,len} 或
    // {ptr,len,owner} 或 SSO 内联）。强解引用会 SIGSEGV → 直接崩 QQ（实测崩溃循环）。
    // 改为只读观测：不解引用、不改写，仅记录"命中过"。
    static int hit_logged = 0;
    if (hit_logged < 3 && is_dlvm_key(key)) {
        hit_logged++;
        LOGI("MMKV set(MMBuffer) dlvm key hit #%d (observe only)", hit_logged);
    }
    return BYTEHOOK_CALL_PREV(fake_mmkv_set_buf, thiz, buf, key);
}

static void fake_mmkv_set_bool(void* thiz, bool v, void* key) {
    BYTEHOOK_STACK_SCOPE();
    // 【T17】只观测不干预（bool 在 ARM64 是 w 寄存器，签名容错）
    static int hit_logged = 0;
    if (hit_logged < 3 && is_dlvm_key(key)) {
        hit_logged++;
        LOGI("MMKV set(bool) dlvm key hit #%d val=%d (observe only)", hit_logged, (int) v);
    }
    BYTEHOOK_CALL_PREV(fake_mmkv_set_bool, thiz, v, key);
}

// 【T16b】libmmkv.so 是 QQ 从 base.apk 直接 mmap 加载的（并非 dlopen），
// 所以 dlopen("libmmkv.so", RTLD_NOLOAD) 返回 NULL。必须先用 dl_iterate_phdr
// 从已加载的 phdr 列表里拿到它的真实路径，再按完整路径 dlopen(RTLD_NOLOAD)。
static char g_mmkv_path[512] = {0};

static int find_mmkv_cb(struct dl_phdr_info* info, size_t sz, void* data) {
    (void) sz; (void) data;
    if (!info || !info->dlpi_name) return 0;
    if (!strstr(info->dlpi_name, "libmmkv")) return 0;
    strncpy(g_mmkv_path, info->dlpi_name, sizeof(g_mmkv_path) - 1);
    g_mmkv_path[sizeof(g_mmkv_path) - 1] = 0;
    return 1;
}

void install_hooks_mmkv() {
    // 【T18 紧急停止】MMKV hook 已验证会导致 QQ 崩溃循环（装上后约 5-6 秒即死）。
    // 崩溃点：libmmkv 的 set 系列符号签名/调用约定与实际不符，或 hook 时机在
    // libmmkv 初始化过程中破坏其内部状态。当前优先级 = QQ 稳定运行。
    // 通过 conf 的 ENABLE_MMKV_HOOK 控制，默认关闭。
    static bool started = false;
    if (started) return;
    started = true;
    LOGI("MMKV hook DISABLED (T18: caused crash loop; re-enable only with ENABLE_MMKV_HOOK)");
    return;
}


// ---------------------------------------------------------------------------

void install_hooks() {
    install_hooks_mmkv();
    LOGI("Installing libc hooks (ByteHook, probe=%d)...", (int)g_probe);

#define HOOK_ALL(sym, fn)                                                        \
    do {                                                                         \
        bytehook_stub_t stub = bytehook_hook_all(nullptr, sym, (void*)(fn),      \
                                                 nullptr, nullptr);              \
        if (!stub) LOGW("hook %s failed", sym);                                  \
    } while (0)

    HOOK_ALL("fopen", fake_fopen);
    HOOK_ALL("fopen64", fake_fopen64);
    HOOK_ALL("fgets", fake_fgets);
    // prctl 拦截已停用：QQ 会自检 PR_SET_DUMPABLE 是否真的生效，\n    // 发现被拦会直 VM exiting（结果码 0）自杀，表现为点登录即闪退。\n    // HOOK_ALL("prctl", fake_prctl);

    HOOK_ALL("open", fake_open);
    HOOK_ALL("open64", fake_open64);
    HOOK_ALL("openat", fake_openat);
    HOOK_ALL("openat64", fake_openat64);
    HOOK_ALL("__open_2", fake_open_2);
    HOOK_ALL("__openat_2", fake_openat_2);

    HOOK_ALL("readlink", fake_readlink);
    HOOK_ALL("access", fake_access);
    HOOK_ALL("stat", fake_stat);
    HOOK_ALL("lstat", fake_lstat);
    HOOK_ALL("fstatat", fake_fstatat);

    HOOK_ALL("__system_property_get", fake___system_property_get);
    HOOK_ALL("__system_property_read_callback", fake___system_property_read_callback);
    // T22: PCDN 路径用 find + read_callback
    HOOK_ALL("__system_property_find", fake___system_property_find);
    HOOK_ALL("uname", fake_uname);
    // libz deflate：抓 Turing 加密前明文（调用者过滤在 fake_deflate 内）
    HOOK_ALL("deflate", fake_deflate);
    // .android_lq 写 fd 跟踪：open 记录 fd，fake_write 抓写入内容
    // 注意：不 hook __write_chk（4 参数 fortify 版，参数错位会触发
    // FORTIFY: write: prevented N-byte read from M-byte buffer 崩溃）
    HOOK_ALL("write", fake_write);
    // 最小化 syscall 观测（仅 .android_lq 路径，零分配）：定位写入函数
    HOOK_ALL("syscall", fake_syscall);
    // DLVM 判定值正常化：memcpy/strcpy/strncpy 里 "failed!" -> "end"
    HOOK_ALL("memcpy", fake_memcpy);
    HOOK_ALL("strcpy", fake_strcpy);
    HOOK_ALL("strncpy", fake_strncpy);
    // 注：syscall() hook 会在 bionic 线程 TLS/malloc 路径里递归，导致 :tool 等进程在 pthread_exit 时 SIGSEGV，已移除。
#undef HOOK_ALL

    // 调用者归因：先把模块表解析出来，并把 fekit/turing/msf 的加载区间报出来
    if (g_attr_on) {
        mod_resolve();
        ModEntry snap[8];
        int reported = 0;
        {
            std::lock_guard<std::mutex> lk(g_mods_lock);
            int n = __atomic_load_n(&g_mods_n, __ATOMIC_ACQUIRE);
            for (int i = 0; i < n && reported < 8; i++) {
                if (g_mods[i].kind != 0) snap[reported++] = g_mods[i];
            }
        }
        for (int i = 0; i < reported; i++) {
            LOGI("ATTR module: %s %p-%p kind=%d", snap[i].name, (void*) snap[i].lo,
                 (void*) snap[i].hi, snap[i].kind);
        }
        if (reported == 0) {
            LOGI("ATTR: libfekit/libturing not mapped yet (lazy resolve armed)");
        }
    }

    // 自检：确认属 hook 是否真的生效
    char vbuf[92] = {0};
    __system_property_get("ro.boot.verifiedbootstate", vbuf);
    LOGI("Self-test ro.boot.verifiedbootstate='%s' (fake target='%s')", vbuf,
         g_boot_state[0] ? g_boot_state : "(off)");

    char hbuf[128] = {0};
    __system_property_get("ro.build.host", hbuf);
    LOGI("Self-test ro.build.host='%s' (fake target='%s')", hbuf,
         g_rom_host[0] ? g_rom_host : "(off)");
    char dbuf[128] = {0};
    __system_property_get("ro.build.display.id", dbuf);
    LOGI("Self-test ro.build.display.id='%s' (fake target='%s')", dbuf,
         g_rom_display[0] ? g_rom_display : "(off)");
    char fbuf[128] = {0};
    __system_property_get("ro.build.fingerprint", fbuf);
    LOGI("Self-test ro.build.fingerprint='%s' (fake target='%s')", fbuf,
         g_rom_fingerprint[0] ? g_rom_fingerprint : "(off)");

    char sbuf[128] = {0};
    __system_property_get("ro.serialno", sbuf);
    LOGI("Self-test ro.serialno='%s' (fake target='%s')", sbuf,
         g_fake_serial[0] ? g_fake_serial : "(off)");
    if (g_fake_soc[0]) {
        FILE* sf = fake_fopen("/sys/devices/soc0/serial_number", "r");
        if (sf) {
            char socbuf[128] = {0};
            size_t n = fread(socbuf, 1, sizeof(socbuf) - 1, sf);
            socbuf[n] = 0;
            LOGI("Self-test soc_serial='%s' (fake target='%s')", socbuf, g_fake_soc);
            fclose(sf);
        }
    }

    if (g_env_on) {
        char ebuf[128] = {0};
        // 【V9】SoC 平台自检：确认 QQ 进程内看到的是伪造值
        // 这一项之前无自检，导致无法判断 hook 是否真生效（k54 破绽的教训）
        {
            char socbuf2[64] = {0};
            __system_property_get("ro.board.platform", socbuf2);
            LOGI("Self-test ro.board.platform='%s' (fake target='kalama')", socbuf2);
            char pb[64] = {0};
            __system_property_get("ro.product.board", pb);
            LOGI("Self-test ro.product.board='%s' (fake target='kalama')", pb);
            char socm[64] = {0};
            __system_property_get("ro.soc.model", socm);
            LOGI("Self-test ro.soc.model='%s' (fake target='SM8650')", socm);
            // /proc/cpuinfo 的 Hardware 行（走 FakeKind 路径）
            FILE* cf = fake_fopen("/proc/cpuinfo", "r");
            if (cf) {
                char line[256];
                while (fgets(line, sizeof(line), cf)) {
                    if (strncmp(line, "Hardware", 8) == 0) {
                        LOGI("Self-test /proc/cpuinfo %s", line);
                        break;
                    }
                }
                fclose(cf);
            }
        }

        __system_property_get("ro.build.version.release", ebuf);
        LOGI("Self-test env release='%s' (target='%s')", ebuf, g_env[0]);
        __system_property_get("ro.build.version.sdk", ebuf);
        LOGI("Self-test env sdk='%s' (target='%s')", ebuf, g_env[1]);
        __system_property_get("ro.build.display.id", ebuf);
        LOGI("Self-test env display='%s' (target='%s')", ebuf, g_env[3]);
        const char* vp = "/proc/version";
        FILE* vf = fake_fopen(vp, "r");
        if (vf) {
            char vbuf2[256] = {0};
            size_t n = fread(vbuf2, 1, sizeof(vbuf2) - 1, vf);
            vbuf2[n] = 0;
            LOGI("Self-test /proc/version='%s'", vbuf2);
            fclose(vf);
        } else {
            LOGW("Self-test /proc/version fake failed");
        }
        struct utsname un;
        if (uname(&un) == 0) {
            LOGI("Self-test uname release='%s' version='%s'", un.release, un.version);
        }
    }

    LOGI("libc hooks installed");
}

} // namespace hook_libc
