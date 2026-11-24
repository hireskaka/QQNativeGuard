# 错误结论清理（2026-11-25）

> 记录本项目中**被证伪或修正过的判断**，避免后续重复踩坑。

## 一、已被证伪的结论

### ❌ 错误 1：「上报点只有 4 个」

**当时的依据**：hook `MsfCore.sendSsoMsg` 只看到 4 类命令。

**证伪**：抓包 539MB 后发现至少 10 个 SDK 出网：
```
MSF(701类) Bugly(449) RMonitor(321) Turing(312) Qimei(268)
Beacon(185) Mars(81) Statistics(72) fekit(51) http-net(426)
```

**教训**：**靠 hook 日志推断全集必然遗漏**，必须抓包验证。

**修正后的结论**：设备信息确实只走 4（现为 5）个通道，但**出网 SDK 远多于 4 个**。

---

### ❌ 错误 2：「心跳停止 = 自杀前兆」

**当时的依据**：18:08 会话心跳在 18:09 停了，20:11 自杀。

**证伪**：20:48 会话心跳也在 20:49 停了，但 21:15 恢复了，没有自杀。

**真相**：心跳与 App 前后台状态相关，**不是自杀前兆**。

---

### ❌ 错误 3：「ProcessBuilder command intercepted = 我们拦截了命令」

**当时的依据**：日志里每分钟出现这条。

**证伪**：代码注释明确写「We don't block it, just log」，**日志措辞有误导性**。

**修正**：把日志文案改为「observed」更准确（待改）。

---

### ❌ 错误 4：「网络切换导致会话断开」

**当时的依据**：看到 `PTC.CONN.LanHeartbeat: NO_CELLULAR` 和 `Account not logged in`。

**证伪**：那是 **pid 6648（OPPO 的 PTC 服务）** 的日志，与 QQ 完全无关。
`Account not logged in` 指 OPPO 账号，不是 QQ。

**教训**：**必须确认日志的 PID/包名归属**，不能看到关键词就归因。

---

### ❌ 错误 5：「w21 是登录时被拒绝」

**当时的依据**：看到登录后立刻弹 w21。

**证伪**（用户指出）：登录**成功**了（QsecEst 已上报），8 秒后 w21 是**异步 push**。

**修正**：w21 走 `SsoHeartBeat` 异步通道，与登录流程无关。

---

### ❌ 错误 6：「k54 来源是 ro.board.platform」

**当时的依据**：两个属性值都是 `lahaina`，看起来对。

**证伪**：T9 文档写明 `k54 ← ro.product.board`。这是我们 hook 的属性之外另一个。

**影响**：导致「自检显示已伪装，实际上报仍是真值」，白费了一轮。

**教训**：**必须用字段映射表逐项核对，不能凭属性名"看起来像"就 hook**。

---

### ❌ 错误 7：「用 root shell 审计能代表 QQ 所见」

**当时的依据**：`adb shell` 读到的值与预期不符就判定"缺口"。

**证伪**：root shell 是 `u:r:ksu:s0` 域，QQ 是 `untrusted_app` 域，**两者看到的世界不同**。

**误判的三项**：
- `/proc/<pid>/cmdline` 可见 magiskd → QQ 无 ptrace 权限，读不到
- `/proc/net/unix` 可见 lspd → SELinux 阻止
- `isXposedInstalled` hook 失败 → 方法根本不存在

**教训**：**审计必须用与目标进程相同的域**（`run-as` 或进程内自检）。

---

### ❌ 错误 8：「MMKV hook 只是改写逻辑有问题」

**当时的依据**：以为改 MMBuffer 布局就能修好。

**证伪**：即使是**纯观测不改写**的实现也会崩（5-6 秒一次）。

**真相**：问题在 `bytehook_hook_single` 本身破坏了 libmmkv 内部状态。

---

## 二、被修正的判断

### 🔄 修正 1：8080 端口是 MSF 主协议，不是 RMonitor

**原判断**：`220.194.118.230:8080` 是 RMonitor 通道。

**修正**（T21 实证）：
- `classes18.dex` 服务器表里与 `msfwifi.3g.qq.com:8080` 同表
- 同网段有 UDP:23000（MSF UDP 通道）
- 帧头是 MSF `SimpleHead`

**结论**：是 MSF 主协议网关。

---

### 🔄 修正 2：「设备指纹四通道」→ 五通道

**原清单**：
```
① QsecEst ② HTTP UA ③ MSF 8080 ④ VOD_MSDK
```

**补充第五通道**：
```
⑤ wlogin GUID (files/wlogin_device.dat + 4 个 MMKV 键)
```

---

### 🔄 修正 3：「wtlogin.device_lock 拦截」是隐患不是现状

**表面**：`BLOCK_COMMANDS` 里有它。

**实际**：因 `NETWORK_OBSERVE_ONLY=true`，`shouldBlock()` 首行即 `return false`，**从未生效**。

**处置**：已移除（消除未来关闭观测模式时的隐患）。

---

## 三、方法论修正

| 错误做法 | 正确做法 |
|---|---|
| 靠 hook 日志推断上报点全集 | **抓包验证** |
| 凭属性名相似就 hook | **用字段映射表逐项核对** |
| 用 root shell 审计 | **用目标进程相同域（run-as）** |
| 看到关键词就归因 | **先确认 PID/包名归属** |
| 假设日志措辞准确 | **读代码确认实际行为** |
| 假设「改了 A 就生效」 | **解密/抓包端到端验证** |

## 四、当前可信结论（经多重验证）

| 结论 | 验证方式 |
|---|---|
| k54 来源 = `ro.product.board` | 解密 QsecEst 实测（修复后变 kalama） |
| 设备信息走 5 个通道 | 抓包 + 解密 + MMKV 分析 |
| `w21` = 服务端账号信用（RiskType 1/201） | 腾讯官方文档 + 三方一致 |
| 账号维度本地无解 | 官方文档 + 参考项目 + 上游作者 + 我们实测 |
| `sp_imei` 装的是 AndroidID | MMKV 二进制直接读取 |
| wlogin GUID 有 5 处存储 | 文件系统 + MMKV 键名分析 |
| 四层独立判定机制 | 三种下线方式的日志特征区分 |