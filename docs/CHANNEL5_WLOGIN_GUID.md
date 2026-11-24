# 第 5 设备指纹通道：wlogin GUID（2026-11-25 完成查证）

> 这是之前 4 通道清单里**完全遗漏**的一条独立身份。

## 一、发现过程

外部调研后新增 `oicq.wlogin_sdk.tools.util` 探测，首次运行即捕获：

```
[WLOGIN-UTIL] generateGuid() -> byte[16] <16-byte-guid>
```

与该值对比：与 `FAKE_ANDROID_ID` / `FAKE_SERIAL` / `FAKE_QIMEI36` **均不相同**，
确认是独立派生量。

## 二、本质：wlogin 自维护的 android_id

MMKV 中的键名揭示了它的真实身份：

```
WLOGIN_DEVICE_INFO_@Stri_android_id  →  <16-byte-guid>
```

**`generateGuid()` 返回的 16 字节 = wlogin 自己维护的 `android_id`**，
与系统 `Settings.Secure.ANDROID_ID` 是**两个独立的东西**。

这就是为什么我们改了系统 AndroidID，wlogin 层仍是旧值。

## 三、完整存储位置（5 处，必须同步）

| # | 位置 | 键名 / 说明 |
|---|---|---|
| ① | `files/wlogin_device.dat` | 裸 16 字节，无 header / 无加密 / 无校验 |
| ② | `files/mmkv/wtlogin_mmkv_file` | `WLOGIN_DEVICE_INFO_@Stri_android_id` |
| ③ | `files/mmkv/wtlogin_mmkv_file` | `WLOGIN_DEVICE_INFO_@Stri_last_android_id`（历史值） |
| ④ | `files/mmkv/wtlogin_mmkv_file` | `WLOGIN_DEVICE_INFO_@Stri_last_guid`（历史值） |
| ⑤ | `files/mmkv/msf_mmkv_file` | `sp_msf_common_@Stri_msf_guid`（MSF 共享同一值） |

**关键**：同一个 GUID 同时充当 **wlogin 的 android_id** 和 **MSF 的 msf_guid**，
两条上报通道共享。

**`last_*` 的存在意味着**：QQ 可能通过「当前值 vs 上次值」判断身份是否变化过 ——
如果只改当前值不改 last 值，可能反被识别为「身份刚变过」。

## 四、文件特征

```
-rw------- 1 u0_a369 u0_a369 16  2026-11-22 18:26  wlogin_device.dat
```

- **正好 16 字节**
- **无任何配套校验文件**（不像 `.android_lq` 需要删 6FAc 缓存）
- **生成于首次登录**（2026-11-22 18:26），此后不变

比 QsecEst 的 `.android_lq` 简单得多：没有 AES、没有 MD5 头、没有派生链。

## 五、顺带查明的其他 wlogin 敏感项

同一 MMKV 文件里还有：

| 键 | 值 | 性质 |
|---|---|---|
| `WLOGIN_DEVICE_INFO_@Stri_ksid` | `<32-hex-ksid>` | 会话密钥 |
| `WLOGIN_DEVICE_INFO_@Stri_rsa_pubkey` | `30818902818100d567...` | 登录握手 RSA 公钥 |
| `WLOGIN_DEVICE_INFO_@Stri_rsa_privkey` | `3082025c02010002818100d567...` | ★ **RSA 私钥** |
| `WLOGIN_DEVICE_INFO_@Stri_last_mac` | — | 历史 MAC |
| `WLOGIN_DEVICE_INFO_@Stri_android_id` | 见上 | 本通道主体 |

**RSA 密钥对说明**：这是登录握手的密钥，**每台设备独立生成**。
如果服务端认为「同一设备应始终用同一密钥对」，那它也是一个可识别的锚点。

## 六、修改方法（待实施）

需同步 5 处。风险点：

1. **MMKV 文件不能直接文本编辑**（是二进制格式，含长度前缀）
2. 必须 QQ 停止运行时操作，否则会被内存中的值覆盖回去
3. `last_*` 值需一并处理，避免「身份刚变过」的判定

**建议顺序**：
```
1. 停 QQ
2. 改 wlogin_device.dat（最简单的裸文件）
3. 改 4 个 MMKV 键（用 hook 层改，或精确二进制替换）
4. 重启验证 generateGuid() 返回新值
```

## 七、这解决了一个悬而未决的问题

之前困惑「为什么改了 AndroidID，某些上报仍是旧值」——
现在知道 wlogin 有独立副本，且 `generateGuid()` 才是登录握手实际用的值。

## 八、待办

- [ ] 实施 GUID 轮换（5 处同步）
- [ ] 验证 `generateGuid()` 返回值变化
- [ ] 确认 `last_*` 值的正确处理方式
- [ ] 决定是否一并轮换 RSA 密钥对