package io.github.kida.qqnativeguard.hooks;

import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.kida.qqnativeguard.XposedEntry;
import io.github.kida.qqnativeguard.config.HookConfig;
import io.github.kida.qqnativeguard.utils.HookUtils;

/**
 * Network Report Interception Hook
 *
 * Intercepts and blocks security-related reporting to Tencent servers:
 * - trpc.o3.report.* (environment reports)
 * - trpc.o3.mobile_security.* (security checks)
 * - TuringFD risk detection
 * - Wlogin device fingerprint
 *
 * 9.3.50 适配说明：
 * - ChannelProxyExt.sendMessage 是抽象方法（hook 不了），实际发送走 sendMessageInner / send，已覆盖。
 * - MsfCore 类在进程早期可能还没加载，改为轮询重试 hook（2 秒一次，最长 30 秒），
 *   并尝试多个候选类名，避免 ClassNotFoundException 导致拦截失效。
 */
public class NetworkReportHook {

    private static final String[] BLOCK_COMMANDS = {
        "trpc.o3.report",
        "trpc.o3.mobile_security",
        "trpc.ilive_cdn.report",
        "OidbSvc.0xd79",  // Device report
        // 【移除】wtlogin.device_lock —— 登录校验类命令，绝不能拦。
        // 外部实证（WeChatTablet README changelog）：
        //   误拦此命令会导致 "身份验证失败 (w21)"
        // "wtlogin.device_lock",
        "turing",
        "riskCheckWup",
        "DeviceTokenV3",
        // 【移除】wtlogin.log_report —— 纯登录日志，拦截无收益且可能引发异常
        // "wtlogin.log_report",
        "QQStranger.login_svr.SsoLoginInfoReport",
    };

    /** 观测名单：这三条之前漏拦，先记录发送内容再决定拦截 */
    private static final String[] OBSERVE_COMMANDS = {
        "trpc.gc_indust.device_report.SsoHome.SsoHomeReport",
        "QQStranger.login_svr.SsoLoginInfoReport",
        "wtlogin.log_report"
    };

    private static boolean isObserveCommand(String command) {
        if (command == null) return false;
        for (String c : OBSERVE_COMMANDS) {
            if (command.contains(c)) return true;
        }
        return false;
    }

    /**
     * 全量 wup 落盘：logcat 只有 1MB、且 observe 摘要只存前 64B，
     * 登录窗口真正的大 payload（如 602/642B log_report）尾部会被截掉。
     * 这里直接追加写文件（不经 FileLog 的去重/轮转），供离线逐字节分析。
     */
    private static void dumpWup(String command, byte[] wup) {
        if (wup == null || wup.length == 0) return;
        try {
            java.io.File f = new java.io.File(WUP_DUMP_PATH);
            java.io.File parent = f.getParentFile();
            if (parent != null && !parent.isDirectory()) parent.mkdirs();
            int cap = Math.min(wup.length, 16384);
            StringBuilder sb = new StringBuilder(cap * 2 + 128);
            sb.append(System.currentTimeMillis()).append(' ').append(command)
              .append(" len=").append(wup.length).append(" hex=");
            for (int i = 0; i < cap; i++) {
                int v = wup[i] & 0xff;
                sb.append(HEX_DIGITS[v >> 4]).append(HEX_DIGITS[v & 0xf]);
            }
            sb.append('\n');
            java.io.FileOutputStream fos = new java.io.FileOutputStream(f, true);
            try {
                fos.write(sb.toString().getBytes("UTF-8"));
            } finally {
                fos.close();
            }
        } catch (Throwable ignored) {
            // 取证失败绝不能影响 QQ
        }
    }

    private static final char[] HEX_DIGITS = "0123456789abcdef".toCharArray();
    private static final String WUP_DUMP_PATH =
        "/storage/emulated/0/Android/data/com.tencent.mobileqq/wup_dump.log";

    /** MsfCore 的候选类名（不同版本/进程可能不同） */
    private static final String[] MSF_CLASS_CANDIDATES = {
        "com.tencent.qphone.base.remote.MsfCore",
        "com.tencent.mobileqq.msf.core.MsfCore",
        "com.tencent.qphone.base.remote.MsfService"
    };

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        // 【T15 修正】观测与拦截分离：
        //   OBSERVE_ONLY=true  → 挂全部 hook 但 shouldBlock() 恒 false（只记录不拦截）
        //   ENABLE_NETWORK_INTERCEPT=false → 完全跳过本次 hook 安装（旧行为，会丢失全部观测）
        // 现在即使不拦截也仍然观测，wup_dump 继续生成。
        if (!HookConfig.ENABLE_NETWORK_INTERCEPT && !HookConfig.NETWORK_OBSERVE_ONLY) return;

        XposedEntry.log("Initializing Network Report Hook (observeOnly="
            + HookConfig.NETWORK_OBSERVE_ONLY + ")");

        // Hook 1: ChannelProxyExt（sendMessage 抽象，由 sendMessageInner/send 覆盖）
        hookChannelProxyExt(lpparam);

        // Hook 2: MsfCore.sendSsoMsg（类晚加载 → 轮询重试）
        for (String className : MSF_CLASS_CANDIDATES) {
            hookMsfCoreWithRetry(className, 30000);
        }

        // Hook 3: TuringFD risk detection
        hookTuringFD(lpparam);

        // Hook 4: Wlogin device report
        hookWlogin(lpparam);

        // Hook 5: wtlogin Reporter / report_t（log_report 明文组装与落盘，纯观测）
        hookWloginReporter(lpparam);

        // Hook 6: QsecEst.d()（T8 定位：事件上报唯一加密通道入口，fekit native 0x1401b8）
        hookQsecEst(lpparam);
    }

    /**
     * T8 定位（docs/SUBAGENT_T8.md）：
     *   com.tencent.mobileqq.qsec.qsecest.QsecEst.d(Context, String, String) -> byte[]
     *   = libfekit.so JNI RegisterNatives@0x890d4 注册的 native 实现 sub_1401B8 (0x1401b8)
     * args[1]/args[2] = 明文输入；返回值 = 加密后上报报文（含 "00002" 信封）
     * 这是 MsfCore.sendSsoMsg 层看不见的事件上报通道 —— 观测 + 未来改写点。
     */
    /**
     * QSEC 通道模式（见 docs/QSEC_EXPERIMENT_PLAN.md）：
     *   文件 /storage/emulated/0/Android/data/com.tencent.mobileqq/qsec_mode.txt
     *   observe(默认) / empty(空数组) / null / blank(同长全零) /
     *   forge(用 qsec_forge.bin 替换，长度可变，T9 已解出加密链可任意构造)
     */
    private static final String QSEC_MODE_PATH =
        "/storage/emulated/0/Android/data/com.tencent.mobileqq/qsec_mode.txt";
    private static final String QSEC_FORGE_PATH =
        "/storage/emulated/0/Android/data/com.tencent.mobileqq/qsec_forge.bin";
    private static volatile String qsecMode = null;
    private static byte[] qsecForge = null;
    private static long qsecModeReadAt = 0;

    private static String qsecMode() {
        long now = System.currentTimeMillis();
        if (qsecMode == null || now - qsecModeReadAt > 3000L) {
            qsecModeReadAt = now;
            String v = null;
            try {
                java.io.File f = new java.io.File(QSEC_MODE_PATH);
                if (f.exists()) {
                    byte[] b = new byte[64];
                    java.io.FileInputStream in = new java.io.FileInputStream(f);
                    int n;
                    try { n = in.read(b); } finally { in.close(); }
                    if (n > 0) {
                        v = new String(b, 0, n, "UTF-8").trim().toLowerCase();
                    }
                }
            } catch (Throwable ignored) {
            }
            qsecMode = (v == null || v.isEmpty()) ? "observe" : v;
        }
        return qsecMode;
    }

    /** 读取 forge 报文（每次现读，支持运行期替换文件） */
    private static byte[] qsecForgeBytes() {
        try {
            java.io.File f = new java.io.File(QSEC_FORGE_PATH);
            if (!f.exists() || f.length() <= 0 || f.length() > 65536) return null;
            byte[] b = new byte[(int) f.length()];
            java.io.FileInputStream in = new java.io.FileInputStream(f);
            int n;
            try { n = in.read(b); } finally { in.close(); }
            if (n <= 0) return null;
            if (n == b.length) return b;
            byte[] o = new byte[n];
            System.arraycopy(b, 0, o, 0, n);
            return o;
        } catch (Throwable t) {
            return null;
        }
    }

    private static void hookQsecEst(final XC_LoadPackage.LoadPackageParam lpparam) {
        final String cls = "com.tencent.mobileqq.qsec.qsecest.QsecEst";
        final long deadline = System.currentTimeMillis() + 60000;
        new Thread(new Runnable() {
            @Override
            public void run() {
                ClassLoader[] loaders = new ClassLoader[]{
                    lpparam.classLoader,
                    NetworkReportHook.class.getClassLoader(),
                    ClassLoader.getSystemClassLoader()
                };
                while (System.currentTimeMillis() < deadline) {
                    for (ClassLoader cl : loaders) {
                        if (cl == null) continue;
                        try {
                            Class<?> c = Class.forName(cls, false, cl);
                            if (c == null) continue;
                            for (Method m : c.getDeclaredMethods()) {
                                if (!"d".equals(m.getName())) continue;
                                Class<?>[] pt = m.getParameterTypes();
                                if (pt.length != 3) continue;
                                if (!pt[0].getName().equals("android.content.Context")) continue;
                                if (!pt[1].getName().equals("java.lang.String")) continue;
                                if (!pt[2].getName().equals("java.lang.String")) continue;
                                XposedBridge.hookMethod(m, new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                        try {
                                            Object a1 = param.args[1], a2 = param.args[2];
                                            Object r = param.getResult();
                                            StringBuilder sb = new StringBuilder();
                                            sb.append("in1=").append(a1 == null ? "null"
                                                    : (a1.toString().length() > 300 ? a1.toString().substring(0, 300) + "..." : a1.toString()));
                                            sb.append(" | in2=").append(a2 == null ? "null"
                                                    : (a2.toString().length() > 300 ? a2.toString().substring(0, 300) + "..." : a2.toString()));
                                            if (r instanceof byte[]) {
                                                byte[] b = (byte[]) r;
                                                sb.append(" | out_len=").append(b.length);
                                                StringBuilder h = new StringBuilder(" | out_hex=");
                                                for (int i = 0; i < b.length && i < 64; i++) {
                                                    h.append(String.format("%02x", b[i]));
                                                }
                                                sb.append(h);
                                                dumpWup("QsecEst.d", b);   // 完整落盘
                                            } else {
                                                sb.append(" | out=").append(String.valueOf(r));
                                            }
                                            XposedEntry.log("QSEC_EST " + sb);
                                        } catch (Throwable ignored) {
                                        }
                                    }
                                });
                                // 模式应用（before hook，改写返回值）
                                XposedBridge.hookMethod(m, new XC_MethodHook() {
                                    @Override
                                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                                        String mode = qsecMode();
                                        if ("observe".equals(mode)) return;
                                        Object r = param.getResult();
                                        int len = (r instanceof byte[]) ? ((byte[]) r).length : 0;
                                        if ("empty".equals(mode)) {
                                            param.setResult(new byte[0]);
                                            XposedEntry.log("QSEC_MODE empty: " + len + "B -> 0B");
                                        } else if ("null".equals(mode)) {
                                            param.setResult(null);
                                            XposedEntry.log("QSEC_MODE null: " + len + "B -> null");
                                        } else if ("blank".equals(mode)) {
                                            param.setResult(new byte[len > 0 ? len : 1293]);
                                            XposedEntry.log("QSEC_MODE blank: " + len + "B -> zeros");
                                        } else if ("forge".equals(mode)) {
                                            byte[] f = qsecForgeBytes();
                                            if (f != null && f.length > 0) {
                                                param.setResult(f);
                                                XposedEntry.log("QSEC_MODE forge: " + len + "B -> " + f.length + "B forged");
                                            } else {
                                                XposedEntry.log("QSEC_MODE forge: qsec_forge.bin missing, passthrough");
                                            }
                                        }
                                    }
                                });
                                XposedEntry.log("QsecEst.d hooked (event-report channel) mode=" + qsecMode());
                                return;
                            }
                        } catch (Throwable ignored) {
                        }
                    }
                    try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
                }
                XposedEntry.log("QsecEst.d not found in 60s (class may load later)");
            }
        }).start();
    }

    /**
     * wtlogin 上报观测（Java 层"根"的读取）：
     * - oicq.wlogin_sdk.report.Reporter：7 个 virtual（第 7 个含 "device" 字符串 = 设备上报组装点）
     * - oicq.wlogin_sdk.report.report_t：write_tofile（log_report 明文本地落盘）/ read_fromfile / delete_file
     * 方法名混淆未知 → 反射遍历 getDeclaredMethods 全量 hook，beforeHookedMethod 记录不阻断。
     */
    private static void hookWloginReporter(XC_LoadPackage.LoadPackageParam lpparam) {
        try {
            Class<?> reportT = XposedHelpers.findClass(
                "oicq.wlogin_sdk.report.report_t", lpparam.classLoader);
            Method[] ms = reportT.getDeclaredMethods();
            for (Method m : ms) {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        logReporterCall("report_t." + param.method.getName(), param);
                    }
                });
            }
            XposedEntry.log("WloginReporter armed: report_t (" + ms.length + " methods)");
        } catch (Throwable t) {
            XposedEntry.log("WloginReporter report_t failed: " + t.getMessage());
        }
        try {
            Class<?> reporter = XposedHelpers.findClass(
                "oicq.wlogin_sdk.report.Reporter", lpparam.classLoader);
            Method[] ms = reporter.getDeclaredMethods();
            for (Method m : ms) {
                XposedBridge.hookMethod(m, new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        logReporterCall("Reporter." + param.method.getName(), param);
                    }
                });
            }
            XposedEntry.log("WloginReporter armed: Reporter (" + ms.length + " methods)");
        } catch (Throwable t) {
            XposedEntry.log("WloginReporter Reporter failed: " + t.getMessage());
        }

        // 明文组装点：Reporter.toJasonObj 返回 log_report 的 JSON 明文（加密前的最后形态）
        try {
            Class<?> reporter = XposedHelpers.findClass(
                "oicq.wlogin_sdk.report.Reporter", lpparam.classLoader);
            Method target = null;
            for (Method m : reporter.getDeclaredMethods()) {
                if ("toJasonObj".equals(m.getName()) || "toJsonObj".equals(m.getName())) {
                    target = m;
                    break;
                }
            }
            if (target != null) {
                XposedBridge.hookMethod(target, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object r = param.getResult();
                        if (r == null) return;
                        String s;
                        if (r instanceof String) {
                            s = (String) r;
                        } else if (r instanceof byte[]) {
                            byte[] b = (byte[]) r;
                            StringBuilder h = new StringBuilder();
                            for (int i = 0; i < b.length && i < 4096; i++) {
                                h.append(String.format("%02x", b[i]));
                            }
                            s = "bytes[" + b.length + "]=" + h;
                        } else {
                            s = String.valueOf(r);
                        }
                        XposedEntry.log("WLOGIN_JSON len=" + s.length() + " body=" + s);
                        dumpText("WLOGIN_JSON", s);
                    }
                });
                XposedEntry.log("WloginReporter armed: toJasonObj (plaintext JSON)");
            } else {
                XposedEntry.log("WloginReporter toJasonObj not found");
            }
        } catch (Throwable t) {
            XposedEntry.log("WloginReporter toJasonObj failed: " + t.getMessage());
        }
    }

    /** 明文文本落盘（JSON 等），追加写同一个 dump 文件 */
    private static void dumpText(String tag, String text) {
        if (text == null || text.isEmpty()) return;
        try {
            java.io.File f = new java.io.File(WUP_DUMP_PATH);
            java.io.File parent = f.getParentFile();
            if (parent != null && !parent.isDirectory()) parent.mkdirs();
            String line = System.currentTimeMillis() + " " + tag + " len=" + text.length()
                    + " text=" + text + "\n";
            java.io.FileOutputStream fos = new java.io.FileOutputStream(f, true);
            try {
                fos.write(line.getBytes("UTF-8"));
            } finally {
                fos.close();
            }
        } catch (Throwable ignored) {
        }
    }

    /** 记录一次 Reporter/report_t 调用：方法名 + 参数摘要（String 全文 / byte[] 前 64B hex） */
    private static void logReporterCall(String tag, XC_MethodHook.MethodHookParam param) {
        StringBuilder sb = new StringBuilder("WLOGIN_REPORT ").append(tag);
        for (int i = 0; i < param.args.length; i++) {
            sb.append(" arg").append(i).append("=").append(describeArg(param.args[i]));
        }
        XposedEntry.log(sb.toString());
    }

    private static String describeArg(Object a) {
        if (a == null) return "null";
        if (a instanceof String) return "\"" + a + "\"";
        if (a instanceof byte[]) {
            byte[] b = (byte[]) a;
            StringBuilder h = new StringBuilder("bytes[").append(b.length).append("]=");
            for (int i = 0; i < b.length && i < 64; i++) {
                h.append(String.format("%02x", b[i]));
            }
            return h.toString();
        }
        return a.getClass().getSimpleName();
    }

    private static void hookChannelProxyExt(XC_LoadPackage.LoadPackageParam lpparam) {
        String[] methodNames = {"sendMessageInner", "send"};

        for (String methodName : methodNames) {
            HookUtils.hookAllMethods("com.tencent.mobileqq.channel.ChannelProxyExt", methodName,
                new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        if (param.args.length < 1) return;

                        String command = (String) param.args[0];
                        if (shouldBlock(command)) {
                            XposedEntry.log("Blocked ChannelProxyExt: " + command);

                            // Inject fake response
                            try {
                                Object channelManager = XposedHelpers.callStaticMethod(
                                    XposedHelpers.findClass("com.tencent.mobileqq.channel.ChannelManager",
                                    lpparam.classLoader), "getInstance");

                                XposedHelpers.callMethod(channelManager, "onNativeReceive",
                                    command, new byte[0], 0L);
                            } catch (Throwable t) {
                                // Ignore if injection fails
                            }

                            param.setResult(null);
                        }
                    }
                });
        }

        XposedEntry.log("ChannelProxyExt.sendMessage is abstract, skipped (covered by sendMessageInner/send)");
    }

    /**
     * 轮询重试 hook MsfCore.sendSsoMsg：
     * 类可能晚于 hook 时机才加载，每 2 秒重试一次，直到成功或超时。
     * 注意：必须直接用 XposedBridge.hookAllMethods，不能用 HookUtils（它会吞掉异常，
     * 导致"假成功"日志）。只有真正 hook 成功才打 "Network interception armed"。
     */
    private static void hookMsfCoreWithRetry(final String className, final long timeoutMs) {
        final long deadline = System.currentTimeMillis() + timeoutMs;

        new Thread(new Runnable() {
            @Override
            public void run() {
                while (System.currentTimeMillis() < deadline) {
                    try {
                        Class<?> clazz = XposedHelpers.findClass(className, HookConfig.getClassLoader());
                        XposedBridge.hookAllMethods(clazz, "sendSsoMsg",
                            new XC_MethodHook() {
                                @Override
                                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                    if (param.args.length < 1) return;

                                    Object toServiceMsg = param.args[0];
                                    String command = (String) XposedHelpers.callMethod(toServiceMsg, "getServiceCmd");

                                    boolean blocked = shouldBlock(command);
                                    // 取证：观测名单 + 被拦命令都要拿到完整 wup（不改行为，只落盘）
                                    if (isObserveCommand(command) || blocked) {
                                        StringBuilder sb = new StringBuilder();
                                        if (blocked) sb.append("[BLOCK] ");
                                        try {
                                            Object attr = XposedHelpers.callMethod(toServiceMsg, "getAttributes");
                                            sb.append("attrs=").append(String.valueOf(attr));
                                        } catch (Throwable t) { sb.append("attrs=?"); }
                                        try {
                                            byte[] wup = (byte[]) XposedHelpers.callMethod(toServiceMsg, "getWupBuffer");
                                            if (wup != null) {
                                                sb.append(" wup_len=").append(wup.length);
                                                StringBuilder hex = new StringBuilder();
                                                for (int i = 0; i < wup.length && i < 48; i++) {
                                                    hex.append(String.format("%02x", wup[i]));
                                                }
                                                sb.append(" wup48=").append(hex);
                                                dumpWup(command, wup);
                                            }
                                        } catch (Throwable t) { sb.append(" wup=?"); }
                                        XposedEntry.log("OBSERVE MsfCore cmd=" + command + " | " + sb);
                                    }

                                    if (blocked) {
                                        XposedEntry.log("Blocked MsfCore: " + command);

                                        // Return sequence number to simulate success
                                        try {
                                            int seq = (int) XposedHelpers.callMethod(toServiceMsg, "getRequestSsoSeq");
                                            param.setResult(seq);
                                        } catch (Throwable t) {
                                            param.setResult(0);
                                        }
                                    }
                                }
                            });
                        XposedEntry.log("Network interception armed: " + className + ".sendSsoMsg");
                        return; // 成功，停止重试
                    } catch (Throwable t) {
                        try {
                            Thread.sleep(2000);
                        } catch (InterruptedException e) {
                            return;
                        }
                    }
                }
            }
        }).start();
    }

    private static void hookTuringFD(XC_LoadPackage.LoadPackageParam lpparam) {
        // 观测模式：之前 setResult(null) 阻断 Turing 操作，导致其检测任务异常
        // （ClassCastException）→ 上报缺失 → 服务端判"外挂或其他软件影响QQ正常使用"
        // （Turing 数据缺失 = 服务端判异常，见 hook_turingxq.cpp 注释）。
        // 现在只观测不阻断：让 Turing 正常上报。
        String[] turingClasses = {
            "com.tencent.turingfd.sdk.xq.Pomegranate",
            "com.tencent.turingfd.sdk.xq.Blueberry",
            "com.tencent.turingcam.oqKCa"
        };

        for (String className : turingClasses) {
            try {
                HookUtils.hookAllMethods(className, "a", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                        // 观测：记录 Turing 操作，不阻断
                        String cls = param.method.getDeclaringClass().getSimpleName();
                        String desc = "TuringFD observe " + cls + " args=" + param.args.length;
                        XposedEntry.log(desc);
                    }
                });
            } catch (Throwable t) {
                // 类可能未加载，静默
            }
        }
    }

    private static void hookWlogin(XC_LoadPackage.LoadPackageParam lpparam) {
        // Hook Wlogin device fingerprint collection
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // Modify device fingerprint before sending
                    XposedEntry.log("Intercepted Wlogin device fingerprint");
                }
            });
    }

    private static boolean shouldBlock(String command) {
        if (command == null) return false;
        // T15：观测模式下永不拦截，只落盘
        if (HookConfig.NETWORK_OBSERVE_ONLY) return false;

        for (String blockCmd : BLOCK_COMMANDS) {
            if (command.contains(blockCmd)) {
                return true;
            }
        }
        return false;
    }
}
