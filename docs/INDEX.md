# QQ Native Guard 文档索引

> 最后更新：2026-11-25

## 一、按重要性排序

| # | 文档 | 内容 | 状态 |
|---|---|---|---|
| 1 | **[CHANNEL5_WLOGIN_GUID.md](CHANNEL5_WLOGIN_GUID.md)** | ★ 第 5 指纹通道完整查证（文件位置+5处存储+本质） | 2026-11-25 新 |
| 2 | **[FLAW_SP_IMEI.md](FLAW_SP_IMEI.md)** | ★ `sp_imei` 字段装的是 AndroidID（格式矛盾） | 2026-11-25 新 |
| 3 | **[CORRECTIONS.md](CORRECTIONS.md)** | ★ 全部被证伪/修正的结论（8 个错误） | 2026-11-25 新 |
| 4 | [K54_ROOT_CAUSE.md](K54_ROOT_CAUSE.md) | k54 来源是 `ro.product.board` 不是 `ro.board.platform` | 已验证 |
| 5 | [EXTERNAL_RESEARCH.md](EXTERNAL_RESEARCH.md) | 外部资料调研（腾讯 RiskType / 参考项目 / qsign） | 2026-11-25 |
| 6 | [VERIFY_REPORT.md](VERIFY_REPORT.md) | 23 项端到端验证结果 | 23/23 PASS |
| 7 | [DETECTION_AUDIT.md](DETECTION_AUDIT.md) | dex 扫描方法与 13 个已覆盖检测类 | — |
| 8 | [EXPOSURE_AUDIT.md](EXPOSURE_AUDIT.md) | 7 大类暴露面完整清单 | — |
| 9 | [SETUP_REPORT.md](SETUP_REPORT.md) | 项目搭建过程与技术债 | — |

## 二、核心结论速查

### 设备信息走 5 个通道

| # | 通道 | 状态 |
|---|---|---|
| ① | QsecEst 85 字段 | ✅ 已对齐（k54=kalama） |
| ② | HTTP User-Agent | ✅ 已对齐（http.agent 重算） |
| ③ | MSF 8080 | ✅ QIMEI 已对齐 |
| ④ | VOD_MSDK | ✅ 已 hook |
| ⑤ | **wlogin GUID** | ❌ **未处理（2026-11-25 查明）** |

### `w21` 的本质（推断，未证实）

**推断**：服务端账号级判定。**能确认的**：文案是「身份验证失败」，发生在登录成功后（异步 push）。
**不能确认的**：服务端具体用什么判定、权重如何。详见 EVIDENCE_LEVELS.md。

三处旁证（**非独立验证**）：
- 腾讯云文档有 RiskType 表（但可能是另一套系统）
- 参考项目称误拦 device_lock 会导致 w21（我们未复现）
- 上游作者称频繁掉线可能是账号风控

### 四种下线方式的区分

| 类型 | 判据 | 能否本地解决 |
|---|---|---|
| ① w21 账号验证 | `KICK_TO_LOGIN=1` + 文案 | ❌ |
| ② 进程自杀 | `EXIT_SELF status=255` + GuardManager.exit | ⚠️ 可能 |
| ③ 会话过期 | `rst1=17` + `rlen 2377→193` | ✅ 重登 |
| ④ 系统杀进程 | `reason=2 SIGNALED` | — |

## 三、工具清单

| 工具 | 用途 |
|---|---|
| `tools/verify_all2.py` | 23 项端到端验证（分三种视角） |
| `tools/audit_full.sh` | 7 大类暴露面审计 |
| `tools/observe_v4.sh` | 会话监控（按时间戳过滤，不污染） |
| `tools/diag_suicide.sh` | 自杀诊断日志（只记关键行） |
| `tools/api_push.py` | git 不通时用 API 推文件 |
| `tools/create_repo.py` | 创建仓库 |

`tools/archive/` 有 48 个一次性调试脚本（按需查阅）。

## 四、待办（按优先级）

| # | 任务 | 难度 | 价值 |
|---|---|---|---|
| 1 | **修 `sp_imei`**（改 MMKV 值为合法 IMEI） | 低 | ★★★ 消除格式矛盾 |
| 2 | **实施 GUID 轮换**（5 处同步） | 中 | ★★★ 补第 5 通道 |
| 3 | 决定是否轮换 wlogin RSA 密钥对 | 中 | ★★ |
| 4 | 加固 `libnative-memory-library-lib.so` 的 syscall 路径 | 高 | ★★ |
| 5 | 补 `PackageManager` 的 `*AsUser` 变体 | 低 | ★ |
| 6 | 修日志措辞（`intercepted` → `observed`） | 低 | ★ |

## 五、当前环境状态

```
机型: OPPO Find X7 (PGT110 / OPPO_PGT110)
平台: kalama (骁龙 8 Gen 3)  ← k54 修复
Build: UKQ1.231003.002
FP: OPPO/PGT110/OPPO_PGT110:15/UKQ1.231003.002/1710000000:user/release-keys
观测: NETWORK_OBSERVE_ONLY=true（挂 hook 不拦截）
```

**待处理矛盾**：
- `sp_imei` = `<16-hex-android-id>`（AndroidID 形状，应为 15 位 IMEI）
- `wlogin GUID` = `7a7b...cc0d`（独立于我们的伪造体系）

## 六、关键教训（写在最显眼处）

1. **抓包 > hook 日志** —— 靠 hook 推断全会漏
2. **字段映射表逐项核对** —— 不能凭属性名"看起来像"
3. **审计要用目标进程的域** —— root shell ≠ untrusted_app
4. **确认日志的 PID 归属** —— 看到关键词就归因必出错
5. **端到端验证** —— 改了不等于生效（k54 的教训）
6. **日志措辞不可信** —— 读代码确认实际行为