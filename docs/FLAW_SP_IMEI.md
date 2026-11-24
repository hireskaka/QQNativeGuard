# 破绽：`sp_imei` 字段装的是 AndroidID（2026-11-25）

> 这是一个**服务端可直接校验的矛盾**，比设备指纹不一致更硬。

## 一、证据

```
MSF.C.Util_@Stri_sp_imei = <16-hex-android-id>     ← 16 位 hex
我们的 FAKE_IMEI         = <15-digit-imei>      ← 15 位数字（Luhn 有效）
系统 ANDROID_ID          = <16-hex-android-id>     ← 与 sp_imei 完全相同
```

**存储在 `/data/user/0/com.tencent.mobileqq/files/mmkv/msf_mmkv_file`**。

## 二、为什么是矛盾

| 字段名 | 应有形状 | 实际值 | 结论 |
|---|---|---|---|
| `sp_imei` | 15 位数字（Luhn 校验通过） | `<16-hex-android-id>` | ❌ **16 位 hex，是 AndroidID 的形状** |

**服务端只要检查这个字段的格式，立刻知道它不是 IMEI。**

合法 IMEI 特征：
- 15 位纯数字
- 通过 Luhn 校验
- 前 2 位是 TAC 报告机构代码（如 `86` = 中国）

而 `<16-hex-android-id>` 含 `c`/`d` 等字母，**连"数字字符串"都不是**。

## 三、成因推断

QQ 的 `MsfSdkUtils.getIMEI()` 在拿不到真 IMEI 时，有一个 fallback：

```
尝试 getDeviceId() / getImei()
  ↓ 失败（被我们 hook 或权限拒绝）
回退用 AndroidID 顶替
  ↓
写入 sp_imei 键
```

我们的 hook 让 `getImei()` 返回了 `<15-digit-imei>`，但 **MSF 层有独立的获取路径**，
最终落盘的是 AndroidID。

**这与 T13 的教训一致**：Java 层 hook 不等于 MSF 层也生效。

## 四、影响评估

**风险等级：中高**

理由：
1. 这是**格式层面的矛盾**，不需要交叉比对多个通道，单看一个字段就能发现
2. 与「设备被伪造」的判定直接相关
3. 修复成本低（改一个 MMKV 值）

**但要注意**：这个值可能只用于本地缓存，不一定上报。需要验证是否进入上报载荷。

## 五、修复方案

**方案 A：改 MMKV 值为合法 IMEI**（推荐）

```
MSF.C.Util_@Stri_sp_imei = <15-digit-imei>   ← 与 FAKE_IMEI 一致
```

**方案 B：在 MSF 层 hook getIMEI**

找到 `com.tencent.mobileqq.msf.sdk.MsfSdkUtils` 的 IMEI 获取方法，让它返回 `FAKE_IMEI`。

**方案 C：两者都做**

## 六、待验证

- [ ] `sp_imei` 是否进入上报载荷（抓包确认）
- [ ] 修改后是否稳定（QQ 会不回写）
- [ ] MSF 层是否有其它 fallback 字段（如 `sp_android_id`、`sp_mac`）

## 七、顺带发现

同一 MMKV 文件里还有：

| 键 | 说明 |
|---|---|
| `sp_msf_common_@Stri_msf_guid` | 与 wlogin GUID 同值（见 CHANNEL5 文档） |
| `sp_boot_msf_@Long_sp_day_id` | 启动日计数 |
| `Ssp_report_login_@Long_key_report_login_time_millis_today_zero_3402312720_*` | 登录时间统计（含 uin） |