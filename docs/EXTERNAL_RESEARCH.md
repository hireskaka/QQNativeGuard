# 外部资料调研（2026-11-25）

> 首次主动联网检索 QQ 检测/风控的公开资料，用于校正本地逆向结论。

## 一、最重要的发现：`wtlogin.device_lock` 绝不能拦

**来源**：[hswwls/WeChatTablet](https://github.com/hswwls/WeChatTablet) README changelog

> **修正：不得拦截 `wtlogin.device_lock` 等登录校验类命令（误拦会导致"身份验证失败 (w21)"）**

**我们的状态**：`BLOCK_COMMANDS` 里原本有这一项（NetworkReportHook.java:35）。

**当前是否生效**：否。所有历史配置都是 `NETWORK_OBSERVE_ONLY=true`，
`shouldBlock()` 首行即 `return false`，从未真正拦截。

**已处理**：注释掉该项，并写明原因。这消除了一个定时炸弹。

**同批移除**：`wtlogin.log_report`（纯登录日志，拦截无收益但可能引发异常）。

## 二、我们遗漏的 native 检测层

**来源**：同上项目 + 本地实测验证

| 库 | 检测方式 | 我们的覆盖 |
|---|---|---|
| `libfekit.so` | maps/smaps/su/mounts + libart 方法校验 | ✅ 已 hook |
| **`libnative-memory-library-lib.so`** | **`ProcMapsIterator` 读 `/proc/self/maps`，靠"映射异常"判定（不看名字），hook `OpenDexFile`/`Runtime.nativeLoad`** | ⚠️ **部分** |
| `libturingxq.so` / `libturingmfa.so` | Turing 风控 | ⚠️ 部分（deflate 注入） |
| `libqimei.so` | 设备指纹 | ⚠️ 部分 |

**本地实测该库的导入符号**：
```
fopen / fgets / fread / open / read / stat / lstat / mmap / close
syscall        ← ★ 可能绕过我们的 libc hook
```

**结论**：
- `fopen`/`fgets`/`fread` 路径 **我们的 hook 能拦**
- `syscall` 路径 **可能绕过**（待验证/加固）

**它不按名字匹配**（库内无 `bytehook`/`frida` 字符串）→ 靠**映射异常**判定，
即检测「文件已删除的 mmap 映射」这种 hook 框架典型特征。

## 三、Tencent 官方 RiskType 定义（`w21` 有了官方解释）

**来源**：[腾讯云 风险等级说明](https://cloud.tencent.com/document/product/1343/106103)

| RiskType | 含义 |
|---|---|
| **1** | **账号信用低 —— 近期存在因恶意被处罚历史，网络低活跃，被举报** |
| 11 | 疑似低活跃账号，活跃度与正常用户有差异 |
| 2 | 垃圾账号，疑似批量注册小号 |
| 21 | 疑似小号，线上养号 |
| 101 | 批量操作，IP/设备/环境聚集性异常 |
| **201** | **环境风险 —— 环境异常操作 IP/设备/环境存在异常** |
| 2011 | 疑似非常用 IP |
| 2012 | 疑似设备属性聚集 |

**`w21` 对应 RiskType 1 或 201 —— 这是服务端账号信用评分，不是设备指纹问题。**

这印证了本项目的核心结论：设备侧已对齐，剩下的是账号信用。

## 四、上游作者的明确表述

**来源**：[Xalsace/QQEnhancedBypass](https://github.com/Xalsace/QQEnhancedBypass) README

> 本项目经过多轮测试，已没有太大问题，**如过账号还是频繁掉线，可能是账号风控，请尝试QQ会员解决**

**上游作者自己也承认账号风控本地无法解决。**

## 五、另一条完全不同的技术路线：qsign

**来源**：[unidbg-fetch-qsign](https://github.com/fuqiuluo/unidbg-fetch-qsign)

> qsign 是腾讯 NTQQ 协议中广泛使用的**风控与 wup 数据签名字段**。
> 常见方案是通过 unidbg 模拟调用 so 库，但存在假签名的情况。

**思路**：不 hook 客户端，而是**在外部用 unidbg 模拟 libfekit.so 生成合法签名**。

**与我们的路线对比**：

| 路线 | 做法 | 适用场景 |
|---|---|---|
| **我们的（hook）** | 在真机上改 QQ 进程内的返回值 | 使用真机 QQ 客户端 |
| **qsign（外部签名）** | 外部服务生成合法签名 | 协议端/机器人 |

**不适用于我们的场景**（我们要用真机 QQ），但有参考价值。

## 六、参考项目的其他可借鉴点

**WeChatTablet 的 `QQSecurityShield` 七层设计**（值得对比我们的实现）：

| 层 | 内容 | 我们的对应 |
|---|---|---|
| A 上报拦截 | 丢弃风控类 SSO 命令 | ⚠️ 有（但用观测模式） |
| B1 root 检测 | `gathererga`/`LightDeviceUtils`/`ChargeV2Utils`/`wlogin` | ✅ 已覆盖 |
| B2 文件痕迹 | `File.exists/canRead/canExecute/canWrite/isFile/isDirectory/length` | ⚠️ **我们少了 isFile/isDirectory/length** |
| B3 包列表 | **`ApplicationPackageManager` 25 个查询方法**（含 `*AsUser`、`getPackagesForUid`） | ⚠️ 我们只 hook 4 个 |
| B4 文本流 | `BufferedReader.readLine` 清洗 maps | ✅ 有 |
| B5 系统属性 | `ro.debuggable`/`ro.secure`/`ro.kernel.qemu`/`ro.build.type`/`ro.build.tags` | ✅ 有 |
| B6 命令探测 | `Runtime.exec`/`ProcessBuilder` 返回假进程 | ⚠️ 我们只记录不伪造 |
| C 分身指纹 | `wlogin.tools.util` + `Qimei` 的 guid/mac/android_id | ❌ **我们没做** |

**三个明确缺口**：
1. `File` 的 `isFile`/`isDirectory`/`length` 方法（我们只覆盖了 exists/canRead/canExecute/canWrite）
2. `PackageManager` 的全部 25 个方法（我们只有 4 个）
3. `wlogin.tools.util` 的 guid/mac/android_id（登录层的设备指纹）

## 七、其他参考

- [qq风控是什么意思？2026账号风控多久恢复](https://www.zhanghaobang.cn/articles/15) —— 轻度风控 1-3 天可能缓解；持续做加重动作会延长
- [PCQQ 数据解密](https://github.com/QQBackup/QQDecrypt) —— 与检测无关，但可参考 QQ 数据格式
- [为什么需要"设备风险对抗层"](https://github.com/hswwls/WeChatTablet) —— 完整列出 QQ 9.x 的检测面

## 八、结论：外部资料改变的三件事

1. **`wtlogin.device_lock` 必须移除拦截**（已修）—— 这是 `w21` 的一个已知诱因
2. **`libnative-memory-library-lib.so` 是漏掉的检测层**（含 syscall 路径风险）
3. **`w21` = 服务端账号信用（RiskType 1/201），本地无解** —— 官方文档佐证

**未改变的结论**：设备指纹已对齐（k54=kalama 验证），瓶颈在账号信用。