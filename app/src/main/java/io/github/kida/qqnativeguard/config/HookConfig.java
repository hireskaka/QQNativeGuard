package io.github.kida.qqnativeguard.config;

import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.kida.qqnativeguard.utils.FileLog;

/**
 * Central configuration for hook modules
 *
 * 外部配置（Root 设备）：
 * QQ 进程启动时会读取以下路径的纯文本配置文件（按顺序，第一个存在且可读的生效），
 * 用文件中的值覆盖下面编译期默认值；文件中未写的项保持默认值。
 *
 *   1. /storage/emulated/0/Android/data/com.tencent.mobileqq/qqbypass.conf
 *      （推荐：adb 可直接 push/修改，QQ 对自己的 Android/data 目录有读写权限）
 *   2. /data/local/tmp/qqbypass.conf   （主路径，adb + su 最方便写入）
 *   3. /data/adb/qqbypass.conf         （备选路径，Magisk 数据目录）
 *
 * 配置文件格式（每行一个 key=value，# 开头为注释）：
 *
 *   # 功能开关
 *   ENABLE_NATIVE_HOOKS=true
 *   ENABLE_ROOT_BYPASS=true
 *   ENABLE_XPOSED_BYPASS=true
 *   ENABLE_DEBUG_BYPASS=true
 *   ENABLE_DEVICE_SPOOF=true
 *   ENABLE_NETWORK_INTERCEPT=true
 *   ENABLE_RUNTIME_BYPASS=true
 *
 *   # 详细日志
 *   VERBOSE_LOGGING=false
 *
 *   # 设备信息伪造（留空 = 使用真实设备信息）
 *   FAKE_IMEI=
 *   FAKE_ANDROID_ID=
 *   FAKE_SERIAL=
 *
 * 修改配置文件后需重启 QQ 才生效（与 LSPosed 模块开关一致）。
 */
public class HookConfig {

    public static XC_LoadPackage.LoadPackageParam loadPackageParam;
    public static ClassLoader classLoader;

    // Observation-first defaults: do not alter device identity or intercept app/system behavior.
    public static boolean ENABLE_NATIVE_HOOKS = false;
    public static boolean ENABLE_ROOT_BYPASS = false;
    public static boolean ENABLE_XPOSED_BYPASS = false;
    public static boolean ENABLE_DEBUG_BYPASS = false;
    public static boolean ENABLE_DEVICE_SPOOF = false;
    public static boolean ENABLE_NETWORK_INTERCEPT = false;
    /** T15：观测模式——挂 hook 但永不拦截（shouldBlock 恒 false）。用于"行为正常化但仍取证" */
    public static boolean NETWORK_OBSERVE_ONLY = false;
    public static boolean ENABLE_RUNTIME_BYPASS = false;

    // Verbose logging
    public static boolean VERBOSE_LOGGING = false;

    // Fake device info (used when spoofing is enabled)
    public static String FAKE_IMEI = null; // null = use real device info
    public static String FAKE_ANDROID_ID = null;
    public static String FAKE_SERIAL = null;
    // /sys/devices/soc0/serial_number（高通 SoC 序列号，应用可读，换机不变 → 常被用作设备指纹）
    public static String FAKE_SOC_SERIAL = null;
    // 开机完整性状态：设备已解锁 BL，真实值为 orange；伪造为 green
    public static String FAKE_BOOT_STATE = null;

    // 探测日志：输出 QQ 实际读取的敏感属性/文件（排查风控触发点用）
    public static boolean PROBE = false;

    /**
     * 调用者归因（观测）：把 libc 访问的真实发起方（libfekit/libturing/libMSF）写进
     * FKCALL 日志，用来反推 fekit 字节码 VM 到底读了哪些路径。
     * ATTR_PROBE 默认开；ATTR_DEEP 控制是否对 libc 中转层做 backtrace。
     */
    public static boolean ATTR_PROBE = false;
    public static boolean ATTR_DEEP = false;

    // Never clear QIMEI/device identity state automatically. Keep this key only for
    // backwards-compatible parsing; the resetter is intentionally not invoked.
    public static String RESET_QIMEI = null;

    // ROM 身份归一化：FEKit 的 DeviceTokenV3 会原样上报 ro.build.host/user/display.id/fingerprint；
    // 移植 ROM 的 ReVork/Sabrina Carpenter/CN01 是很明显的“非官方系统”特征。
    // 留空 = 不修改。
    public static String ROM_BUILD_HOST = null;
    public static String ROM_BUILD_USER = null;
    public static String ROM_BUILD_DISPLAY = null;
    public static String ROM_BUILD_FINGERPRINT = null;

    // 直接伪造 Qimei SDK 返回给 QQ 的 qimei16/qimei36（服务端如果按 QIMEI 识别设备，
    // 换一个值就等于换设备）。留空 = 使用真实值。
    public static String FAKE_QIMEI36 = null;

    /** 【V11】wlogin generateGuid 伪造值（32 hex chars = 16 字节）
     *  依据：GUID 从存储读取无效，只能 hook 函数返回此值 */
    public static String FAKE_WLOGIN_GUID = null;

    // OPPO OAID（com.heytap.openid 返回的匿名设备 ID）
    public static String FAKE_OAID = null;

    // Environment overrides are opt-in; default leaves platform values untouched.
    public static boolean ENV_SPOOF = false;
    public static String ENV_RELEASE = "14";
    public static String ENV_SDK = "34";
    public static String ENV_BUILD_ID = "UKQ1.230924.001";
    public static String ENV_DISPLAY = "LE2125_14.0.0.730(EX01)";
    public static String ENV_FINGERPRINT =
        "OPPO/LE2125/OnePlus9Pro:14/UKQ1.230924.001/1727136000:user/release-keys";
    public static String ENV_DESCRIPTION =
        "qssi-user 14 UKQ1.230924.001 1727136000 release-keys";
    public static String ENV_HOST = "build";
    public static String ENV_USER = "builder";
    public static String ENV_DATE = "Tue Sep 24 00:00:00 CST 2024";
    public static String ENV_INCREMENTAL = "1727136000";
    public static String ENV_SECURITY_PATCH = "2024-09-05";
    public static String ENV_OPPOROM = "V14.0.0";
    public static String ENV_KERNEL_RELEASE = "5.4.254-qgki-g9e38a9fabb4d";
    public static String ENV_KERNEL_VERSION = "#1 SMP PREEMPT Tue Sep 24 00:00:00 CST 2024";
    public static String ENV_AAID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
    // 机型画像（换机型：LE2123 -> LE2125，同硬件同 SoC）
    public static String ENV_MODEL = "LE2125";
    public static String ENV_PRODUCT_NAME = "OnePlus9Pro";
    public static String ENV_DEVICE = "OnePlus9Pro";
    public static String ENV_BRAND = "OnePlus";
    public static String ENV_MANUFACTURER = "OnePlus";

    // 日志写文件（null/空 = 只打 logcat，不写文件）
    // 例：/data/user/0/com.tencent.mobileqq/qqbypass.log（QQ 可写、root 可读）
    public static String LOG_FILE = null;

    private static final String TAG = "QQEnhancedBypass";

    /** 外部配置文件候选路径：第一个存在且可读的文件生效 */
    private static final String[] EXTERNAL_CONFIG_PATHS = {
        "/storage/emulated/0/Android/data/com.tencent.mobileqq/qqbypass.conf",
        "/data/local/tmp/qqbypass.conf",
        "/data/adb/qqbypass.conf"
    };

    public static void init(XC_LoadPackage.LoadPackageParam lpparam) {
        loadPackageParam = lpparam;
        classLoader = lpparam.classLoader;
        loadExternalConfig();
        // 读取完外部配置后再初始化文件日志（LOG_FILE 来自配置文件）
        FileLog.init(LOG_FILE);
    }

    /**
     * 读取外部配置文件，覆盖编译期默认值。
     * 只读一次，失败静默降级（保持默认配置），不影响模块启动。
     */
    private static void loadExternalConfig() {
        for (String path : EXTERNAL_CONFIG_PATHS) {
            File file = new File(path);
            if (!file.isFile()) {
                continue;
            }
            try (InputStream in = new FileInputStream(file)) {
                Properties props = new Properties();
                props.load(in);

                ENABLE_NATIVE_HOOKS = getBool(props, "ENABLE_NATIVE_HOOKS", ENABLE_NATIVE_HOOKS);
                ENABLE_ROOT_BYPASS = getBool(props, "ENABLE_ROOT_BYPASS", ENABLE_ROOT_BYPASS);
                ENABLE_XPOSED_BYPASS = getBool(props, "ENABLE_XPOSED_BYPASS", ENABLE_XPOSED_BYPASS);
                ENABLE_DEBUG_BYPASS = getBool(props, "ENABLE_DEBUG_BYPASS", ENABLE_DEBUG_BYPASS);
                ENABLE_DEVICE_SPOOF = getBool(props, "ENABLE_DEVICE_SPOOF", ENABLE_DEVICE_SPOOF);
                ENABLE_NETWORK_INTERCEPT = getBool(props, "ENABLE_NETWORK_INTERCEPT", ENABLE_NETWORK_INTERCEPT);
                NETWORK_OBSERVE_ONLY = getBool(props, "NETWORK_OBSERVE_ONLY", NETWORK_OBSERVE_ONLY);
                ENABLE_RUNTIME_BYPASS = getBool(props, "ENABLE_RUNTIME_BYPASS", ENABLE_RUNTIME_BYPASS);
                VERBOSE_LOGGING = getBool(props, "VERBOSE_LOGGING", VERBOSE_LOGGING);
                PROBE = getBool(props, "PROBE", PROBE);
                ATTR_PROBE = getBool(props, "ATTR_PROBE", ATTR_PROBE);
                ATTR_DEEP = getBool(props, "ATTR_DEEP", ATTR_DEEP);

                FAKE_IMEI = getString(props, "FAKE_IMEI", FAKE_IMEI);
                FAKE_ANDROID_ID = getString(props, "FAKE_ANDROID_ID", FAKE_ANDROID_ID);
                FAKE_SERIAL = getString(props, "FAKE_SERIAL", FAKE_SERIAL);
                FAKE_SOC_SERIAL = getString(props, "FAKE_SOC_SERIAL", FAKE_SOC_SERIAL);
                FAKE_BOOT_STATE = getString(props, "FAKE_BOOT_STATE", FAKE_BOOT_STATE);
                LOG_FILE = getString(props, "LOG_FILE", LOG_FILE);
                RESET_QIMEI = getString(props, "RESET_QIMEI", RESET_QIMEI);
                ROM_BUILD_HOST = getString(props, "ROM_BUILD_HOST", ROM_BUILD_HOST);
                ROM_BUILD_USER = getString(props, "ROM_BUILD_USER", ROM_BUILD_USER);
                ROM_BUILD_DISPLAY = getString(props, "ROM_BUILD_DISPLAY", ROM_BUILD_DISPLAY);
                ROM_BUILD_FINGERPRINT = getString(props, "ROM_BUILD_FINGERPRINT", ROM_BUILD_FINGERPRINT);
                FAKE_QIMEI36 = getString(props, "FAKE_QIMEI36", FAKE_QIMEI36);
        FAKE_WLOGIN_GUID = getString(props, "FAKE_WLOGIN_GUID", FAKE_WLOGIN_GUID);
                FAKE_OAID = getString(props, "FAKE_OAID", FAKE_OAID);
                ENV_SPOOF = getBool(props, "ENV_SPOOF", ENV_SPOOF);
                ENV_RELEASE = getString(props, "ENV_RELEASE", ENV_RELEASE);
                ENV_SDK = getString(props, "ENV_SDK", ENV_SDK);
                ENV_BUILD_ID = getString(props, "ENV_BUILD_ID", ENV_BUILD_ID);
                ENV_DISPLAY = getString(props, "ENV_DISPLAY", ENV_DISPLAY);
                ENV_FINGERPRINT = getString(props, "ENV_FINGERPRINT", ENV_FINGERPRINT);
                ENV_DESCRIPTION = getString(props, "ENV_DESCRIPTION", ENV_DESCRIPTION);
                ENV_HOST = getString(props, "ENV_HOST", ENV_HOST);
                ENV_USER = getString(props, "ENV_USER", ENV_USER);
                ENV_DATE = getString(props, "ENV_DATE", ENV_DATE);
                ENV_INCREMENTAL = getString(props, "ENV_INCREMENTAL", ENV_INCREMENTAL);
                ENV_SECURITY_PATCH = getString(props, "ENV_SECURITY_PATCH", ENV_SECURITY_PATCH);
                ENV_OPPOROM = getString(props, "ENV_OPPOROM", ENV_OPPOROM);
                ENV_KERNEL_RELEASE = getString(props, "ENV_KERNEL_RELEASE", ENV_KERNEL_RELEASE);
                ENV_KERNEL_VERSION = getString(props, "ENV_KERNEL_VERSION", ENV_KERNEL_VERSION);
                ENV_MODEL = getString(props, "ENV_MODEL", ENV_MODEL);
                ENV_PRODUCT_NAME = getString(props, "ENV_PRODUCT_NAME", ENV_PRODUCT_NAME);
                ENV_DEVICE = getString(props, "ENV_DEVICE", ENV_DEVICE);
                ENV_BRAND = getString(props, "ENV_BRAND", ENV_BRAND);
                ENV_MANUFACTURER = getString(props, "ENV_MANUFACTURER", ENV_MANUFACTURER);

                Log.i(TAG, "External config loaded from " + path);
                return; // 第一个可读的配置文件生效
            } catch (Throwable t) {
                Log.w(TAG, "Failed to read external config " + path + ": " + t.getMessage());
            }
        }
    }

    /**
     * 解析布尔值：true/1/on/yes 视为 true，其余（含乱写）一律 false。
     * 文件里没写该 key 时返回 fallback（编译期默认值）。
     */
    private static boolean getBool(Properties props, String key, boolean fallback) {
        String value = props.getProperty(key);
        if (value == null) {
            return fallback;
        }
        value = value.trim();
        return "true".equalsIgnoreCase(value)
            || "1".equals(value)
            || "on".equalsIgnoreCase(value)
            || "yes".equalsIgnoreCase(value);
    }

    /**
     * 解析字符串：文件里没写该 key 时返回 fallback；
     * 写了但为空（如 FAKE_IMEI=）时返回 null（= 使用真实设备信息）。
     */
    private static String getString(Properties props, String key, String fallback) {
        String value = props.getProperty(key);
        if (value == null) {
            return fallback;
        }
        value = value.trim();
        return value.isEmpty() ? null : value;
    }

    public static ClassLoader getClassLoader() {
        return classLoader;
    }
}
