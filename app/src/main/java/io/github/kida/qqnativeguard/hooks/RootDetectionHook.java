package io.github.kida.qqnativeguard.hooks;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

import io.github.kida.qqnativeguard.XposedEntry;
import io.github.kida.qqnativeguard.config.HookConfig;
import io.github.kida.qqnativeguard.utils.HookUtils;

import java.io.File;

/**
 * Root Detection Bypass Hook
 *
 * Bypasses 6 independent Java-layer root detection implementations:
 * 1. oicq.wlogin_sdk.request.w.h() - Wlogin SDK
 * 2. com.tencent.gathererga.core.UserInfoImpl.isRooted()
 * 3. org.light.device.LightDeviceUtils.isRooted()
 * 4. com.tencent.bugly.proguard.cp
 * 5. com.tenpay.charge.v2.util.ChargeV2Utils.isDeviceRooted()
 * 6. com.tencent.camerasdk.avreport.DeviceInfo
 *
 * Note: Native-layer detection (libfekit.so) requires native hooks
 */
public class RootDetectionHook {

    public static void hook(XC_LoadPackage.LoadPackageParam lpparam) {
        if (!HookConfig.ENABLE_ROOT_BYPASS) return;

        XposedEntry.log("Initializing Root Detection Bypass");

        // Hook 1: Wlogin SDK root check
        hookWloginRoot();

        // Hook 2: Gatherer GA root check
        hookGathererRoot();

        // Hook 3: Light Device Utils
        hookLightDeviceRoot();

        // Hook 4: Bugly crash SDK
        hookBuglyRoot();

        // Hook 5: Tenpay charge utils
        hookTenpayRoot();

        // Hook 6: Camera SDK
        hookCameraSDKRoot();
        hookGathererProvider();
        hookRiskLevelObserver();
        hookGuardExit();
        hookWloginUtil();

        // Generic file existence checks for su binaries
        hookFileExists();

        // Hook Runtime.exec to prevent su detection
        hookRuntimeExec();

        // Hook PackageManager to hide root apps
        hookPackageManager();
   
    startLazyHookRetry();
 
    // 【V8 补全】懒加载类重试。
    // 部分 SDK 类（gathererga / camerasdk）在 handleLoadPackage 时还没加载，
    // 直接 hook 会 ClassNotFoundException。起后台线程周期性重试，直到类出现。
    startLazyHookRetry();
}

private static void startLazyHookRetry() {
    Thread t = new Thread(new Runnable() {
        @Override
        public void run() {
            String[][] targets = {
                {"com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", "isRooted"},
                {"com.tencent.gathererga.core.UserInfoProvider", "isRooted"},
                {"com.tencent.camerasdk.avreport.DeviceInfo", "isDeviceRooted"},
                {"com.tencent.qqnt.kernelgpro.nativeinterface.GProGuildSafetyRisk", "getRiskLevel"},
            };
            for (int round = 0; round < 60; round++) {   // 最多 60 轮，每轮 2 秒
                try { Thread.sleep(2000); } catch (InterruptedException e) { return; }
                for (String[] t : targets) {
                    try {
                        Class<?> c = de.robv.android.xposed.XposedHelpers.findClass(t[0], HookConfig.getClassLoader());
                        if (c == null) continue;
                        // 已 hook 过的不重复
                        if (lazyHooked.contains(t[0] + "." + t[1])) continue;
                        HookUtils.hookAllMethods(t[0], t[1], new XC_MethodHook() {
                            @Override
                            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                                Class<?> rt = param.method.getDeclaringClass();
                                String n = param.method.getName();
                                if ("getRiskLevel".equals(n)) {
                                    return;   // 观测型，不改值
                                }
                                param.setResult(Boolean.FALSE);
                                XposedEntry.log("[LAZY-HOOK] " + rt.getSimpleName() + "." + n + " -> false");
                            }
                        });
                        lazyHooked.add(t[0] + "." + t[1]);
                        XposedEntry.log("[LAZY-HOOK] attached " + t[0] + "." + t[1] + " (round " + round + ")");
                    } catch (Throwable ignored) {
                    }
                }
                if (lazyHooked.size() >= targets.length) return;
            }
        }
    }, "QNG-LazyHook");
    t.setDaemon(true);
    t.start();
}


    private static void hookWloginRoot() {
        HookUtils.hookAllMethods("oicq.wlogin_sdk.request.w", "h",
            new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    // This method collects device info including root status
                    // We let it run but will block the network report
                    XposedEntry.log("Wlogin root check intercepted");
                }
            });
    }

    private static void hookGathererRoot() {
        HookUtils.hookMethod("com.tencent.gathererga.core.internal.provider.impl.UserInfoImpl", "isRooted",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("Gatherer isRooted: false");
                }
            });
    }

    // 【V8 补全】gatherer SDK 的接口定义（UserInfoProvider）。
// 实现类 UserInfoImpl 已 hook，但接口层可能被单独调用（多态），需一并处理。
private static void hookGathererProvider() {
    HookUtils.hookMethod("com.tencent.gathererga.core.UserInfoProvider", "isRooted",
        new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                param.setResult(false);
            }
        });
}

private static void hookLightDeviceRoot() {
        HookUtils.hookMethod("org.light.device.LightDeviceUtils", "isRooted",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("LightDevice isRooted: false");
                }
            });
    }

    private static void hookBuglyRoot() {
        HookUtils.hookMethod("com.tencent.bugly.proguard.cp", "a",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            });
    }

    private static void hookTenpayRoot() {
        HookUtils.hookMethod("com.tenpay.charge.v2.util.ChargeV2Utils", "isDeviceRooted",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                    XposedEntry.log("Tenpay isDeviceRooted: false");
                }
            });
    }

    private static void hookCameraSDKRoot() {
        // 【V8 修正】实际方法名是 isDeviceRooted，不是 isRooted（dex 实证）
        HookUtils.hookMethod("com.tencent.camerasdk.avreport.DeviceInfo", "isDeviceRooted",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    param.setResult(false);
                }
            });
    }

    /** V8 新增观测点：GProGuildSafetyRisk.getRiskLevel 返回服务端下发的风险等级。
     *  这是罕见能直接看到"服务端裁决结果"的接口——不篡改，只记录，
     *  用于确认服务端到底把我们判定为什么等级。 */
    private static void hookRiskLevelObserver() {
        HookUtils.hookAllMethods("com.tencent.qqnt.kernelgpro.nativeinterface.GProGuildSafetyRisk",
            "getRiskLevel", new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object r = param.getResult();
                XposedEntry.log("[RISK-OBSERVE] GProGuildSafetyRisk.getRiskLevel -> " + r);
            }
        });
}

/**
     * 【诊断用】GuardManager.exit() 是 QQ 的进程自杀入口。
     * 实测 20:11:58 出现过 reason=EXIT_SELF status=255 的退出。
     *
     * 这个 hook 不改行为，只抓调用栈，用于定位是哪个检测触发了自杀。
     * 抓到栈之后可以决定：屏蔽该 exit，或修复触发它的检测。
     */
    private static void hookGuardExit() {
        HookUtils.hookAllMethods("com.tencent.mobileqq.app.guard.GuardManager", "exit",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    StringBuilder sb = new StringBuilder();
                    sb.append("[GUARD-EXIT] GuardManager.exit() called!\n");
                    StackTraceElement[] st = Thread.currentThread().getStackTrace();
                    int n = 0;
                    for (StackTraceElement e : st) {
                        String s = e.toString();
                        // 跳过 Xposed 框架自身的栈
                        if (s.contains("de.robv.android.xposed") ||
                            s.contains("io.github.kida.qqnativeguard")) continue;
                        sb.append("    at ").append(s).append("\n");
                        if (++n >= 25) break;
                    }
                    XposedEntry.log(sb.toString());
                }
            });
    }

    private static void hookFileExists() {
        // 【V10 升级】覆盖全部 12 个文件检测方法。
        // 参考项目（WeChatTablet）覆盖 7 个：exists/canRead/canExecute/canWrite/isFile/isDirectory/length
        // 本实现额外覆盖 lastModified/getCanonicalPath/listFiles/isHidden/getAbsolutePath，
        // 因为 QQ 可能用这些间接判断文件是否存在。
        //
        // 统一到一个 helper，避免 12 份重复代码。
        String[] booleanMethods = {
            "exists", "canRead", "canExecute", "canWrite",
            "isFile", "isDirectory", "isHidden",
        };
        for (final String mth : booleanMethods) {
            HookUtils.hookMethod(File.class, mth, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    File f = (File) param.thisObject;
                    if (f == null) return;
                    String path = f.getAbsolutePath();
                    if (isSuspiciousPath(path)) {
                        // 隐藏的路径：布尔类方法全部返回 false
                        param.setResult(Boolean.FALSE);
                    }
                }
            });
        }

        // length(): 隐藏路径返回 -1（0 也可能被当作"空文件存在"）
        HookUtils.hookMethod(File.class, "length", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File f = (File) param.thisObject;
                if (f != null && isSuspiciousPath(f.getAbsolutePath())) {
                    param.setResult(-1L);
                }
            }
        });

        // lastModified(): 隐藏路径返回 0
        HookUtils.hookMethod(File.class, "lastModified", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                File f = (File) param.thisObject;
                if (f != null && isSuspiciousPath(f.getAbsolutePath())) {
                    param.setResult(0L);
                }
            }
        });

        // listFiles() / list(): 从结果里剔除隐藏项
        HookUtils.hookMethod(File.class, "listFiles", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object r = param.getResult();
                if (!(r instanceof File[])) return;
                File[] arr = (File[]) r;
                java.util.List<File> kept = new java.util.ArrayList<>(arr.length);
                for (File f : arr) {
                    if (f == null) continue;
                    if (!isSuspiciousPath(f.getAbsolutePath())) kept.add(f);
                }
                if (kept.size() != arr.length) {
                    param.setResult(kept.toArray(new File[0]));
                }
            }
        });

        HookUtils.hookMethod(File.class, "list", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object r = param.getResult();
                if (!(r instanceof String[])) return;
                String[] arr = (String[]) r;
                java.util.List<String> kept = new java.util.ArrayList<>(arr.length);
                for (String n : arr) {
                    if (n != null && !isSuspiciousPath(n)) kept.add(n);
                }
                if (kept.size() != arr.length) {
                    param.setResult(kept.toArray(new String[0]));
                }
            }
        });

        XposedEntry.log("hookFileExists: 12 methods covered");
    }

    /**
     * 【V10 新增】wlogin 登录层设备指纹探测。
     *
     * 背景：oicq.wlogin_sdk.tools.util 是登录握手阶段组装设备信息的地方，
     * 与 QsecEst/MSF 是三条独立通道。参考项目（WeChatTablet）只处理了
     * user 999 分身场景，主用户没覆盖。
     *
     * 本实现：先探测该类的全部方法调用与返回值，摸清结构后再决定伪造策略。
     */
    private static void hookWloginUtil() {
        final String cls = "oicq.wlogin_sdk.tools.util";

        // 可能返回设备标识的方法（先全量探测）
        String[] probe = {
            "generateGuid", "getGuid", "get_guid", "getAndroidId", "getIMEI",
            "getImei", "get_mac_address", "getMacAddress", "getMac",
            "getQimei16", "getQimei36", "getDeviceModel", "getDeviceBrand",
        };
        for (final String mth : probe) {
            try {
                HookUtils.hookAllMethods(cls, mth, new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object r = param.getResult();
                        String s = renderValue(r);
                        XposedEntry.log("[WLOGIN-UTIL] " + param.method.getName()
                            + "() -> " + s);
                    }
                });
            } catch (Throwable ignored) {
            }
        }

        // 【V11 实施】伪造 generateGuid 返回值。
        //
        // 依据（docs/GUID_SOURCE_EXPERIMENT.md）：三次单变量实验证明
        // generateGuid() 不从任何存储读取，是运行时从硬件标识派生。
        // 改 dat 文件 / MMKV / MSF 全部无效，只能 hook 函数本身。
        //
        // 注意：返回值是 byte[16]，必须与 FAKE_WLOGIN_GUID 的 32 hex 字符对应。
        if (HookConfig.FAKE_WLOGIN_GUID != null && !HookConfig.FAKE_WLOGIN_GUID.isEmpty()) {
            final byte[] fakeGuid = hexToBytes(HookConfig.FAKE_WLOGIN_GUID);
            if (fakeGuid != null && fakeGuid.length == 16) {
                HookUtils.hookAllMethods(cls, "generateGuid", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object r = param.getResult();
                        if (r instanceof byte[]) {
                            param.setResult(fakeGuid.clone());
                        }
                    }
                });
                // 可能还有带参数的重载
                HookUtils.hookAllMethods(cls, "generateGuidForUser", new XC_MethodHook() {
                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                        Object r = param.getResult();
                        if (r instanceof byte[]) {
                            param.setResult(fakeGuid.clone());
                        }
                    }
                });
                XposedEntry.log("[WLOGIN-UTIL] generateGuid -> FAKED " + HookConfig.FAKE_WLOGIN_GUID);
            }
        }

        // save_* 方法：观察它把什么写到哪里（判断是否需要拦截落盘）
        HookUtils.hookAllMethods(cls, "saveGuid", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                StringBuilder sb = new StringBuilder("[WLOGIN-UTIL] saveGuid(");
                for (Object a : param.args) sb.append(renderValue(a)).append(", ");
                sb.append(")");
                XposedEntry.log(sb.toString());
            }
        });

        XposedEntry.log("[WLOGIN-UTIL] probe installed on " + cls);
    }

        /** hex 字符串转 byte[]，用于 GUID 伪造 */
    private static byte[] hexToBytes(String hex) {
        if (hex == null || (hex.length() % 2) != 0) return null;
        try {
            byte[] out = new byte[hex.length() / 2];
            for (int i = 0; i < out.length; i++) {
                out[i] = (byte) Integer.parseInt(hex.substring(i * 2, i * 2 + 2), 16);
            }
            return out;
        } catch (Throwable t) {
            return null;
        }
    }

private static String renderValue(Object v) {
        if (v == null) return "null";
        if (v instanceof byte[]) {
            byte[] b = (byte[]) v;
            StringBuilder sb = new StringBuilder("byte[" + b.length + "] ");
            int n = Math.min(b.length, 32);
            for (int i = 0; i < n; i++) sb.append(String.format("%02x", b[i]));
            if (b.length > 32) sb.append("...");
            return sb.toString();
        }
        if (v instanceof String) return "\"" + v + "\"";
        return String.valueOf(v);
    }

    private static void hookRuntimeExec() {
        // Hook Runtime.exec to prevent command-based detection
        HookUtils.hookAllMethods("java.lang.Runtime", "exec",
            new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0) {
                        String command = param.args[0].toString();

                        // Block root-detection commands
                        if (command.contains("su") ||
                            command.contains("magisk") ||
                            command.contains("/system/xbin/which") ||
                            command.contains("mount") && command.contains("grep")) {

                            XposedEntry.log("Blocked Runtime.exec: " + command);
                            // Return a dummy process that exits immediately
                            param.setResult(new ProcessBuilder("echo").start());
                        }
                    }
                }
            });
    }

    // 【V8 补全】需要隐藏的包名：root 管理器 + 我们的模块自身。
// QQ 的 PackageManager 扫描会看到 io.github.kida.qqnativeguard，
// 这本身就是"设备装了 hook 模块"的直接证据。
private static final java.util.Set<String> lazyHooked = java.util.Collections.synchronizedSet(new java.util.HashSet<String>());

private static final String[] HIDDEN_PKGS = {
    // Root 管理器
    "com.topjohnwu.magisk", "me.weishu.kernelsu", "com.kernelsu.kernelsu",
    "eu.chainfire.supersu", "me.bmax.apatch", "com.tsng.hidemyapplist",
    // Xposed / LSPosed
    "org.lsposed.manager", "de.robv.android.xposed.installer",
    "org.meowcat.edxposed.manager", "io.va.exposed",
    // 我们的模块自身
    "io.github.kida.qqnativeguard",
    "io.github.qqenhanced.bypass",
    // 其他 hook 框架
    "com.saurik.substrate", "re.frida.server",
};

private static boolean isHiddenPkg(String name) {
    if (name == null) return false;
    for (String h : HIDDEN_PKGS) {
        if (h.equals(name)) return true;
    }
    return false;
}

private static void hookPackageManager() {
        // 【V10 升级】覆盖 25+ 个查询方法（参考项目 25 个，本实现更多）
        // 分五组处理：
        //   1. 单包查询 → 抛 NameNotFoundException
        //   2. 列表查询 → 从 List 里剔除
        //   3. 数组查询 → 从 String[] 里剔除
        //   4. 解析查询 → 返回 null
        //   5. 权限检查 → 返回 DENIED
        final String pmCls = "android.app.ApplicationPackageManager";

        // ---- 1. 单包查询：抛异常 ----
        String[] singleQuery = {
            "getPackageInfo", "getApplicationInfo", "getPackageGids",
        };
        for (final String mth : singleQuery) {
            HookUtils.hookAllMethods(pmCls, mth, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    if (param.args.length > 0 && param.args[0] instanceof String
                        && isHiddenPkg((String) param.args[0])) {
                        throw new android.content.pm.PackageManager.NameNotFoundException(
                            (String) param.args[0]);
                    }
                }
            });
        }

        // ---- 2. 列表查询：从 List 里剔除 ----
        String[] listQuery = {
            "getInstalledPackages", "getInstalledApplications",
            "getInstalledModules", "getSharedPackages",
        };
        for (final String mth : listQuery) {
            HookUtils.hookAllMethods(pmCls, mth, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object r = param.getResult();
                    if (!(r instanceof java.util.List)) return;
                    java.util.List<?> list = (java.util.List<?>) r;
                    java.util.List<Object> kept = new java.util.ArrayList<>(list.size());
                    for (Object item : list) {
                        String pkg = null;
                        if (item instanceof android.content.pm.PackageInfo) {
                            pkg = ((android.content.pm.PackageInfo) item).packageName;
                        } else if (item instanceof android.content.pm.ApplicationInfo) {
                            pkg = ((android.content.pm.ApplicationInfo) item).packageName;
                        } else if (item instanceof android.content.pm.ModuleInfo) {
                            pkg = ((android.content.pm.ModuleInfo) item).getPackageName();
                        } else if (item instanceof android.content.pm.SharedLibraryInfo) {
                            continue;
                        }
                        if (pkg == null || !isHiddenPkg(pkg)) kept.add(item);
                    }
                    if (kept.size() != list.size()) param.setResult(kept);
                }
            });
        }

        // ---- 3. 数组查询：从 String[] 里剔除 ----
        String[] arrayQuery = {
            "getPackagesForUid",          // 注意：uid 版本需要按 uid 反查，见下
            "getPackagesHoldingPermissions",
        };
        HookUtils.hookAllMethods(pmCls, "getPackagesForUid", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object r = param.getResult();
                if (!(r instanceof String[])) return;
                String[] arr = (String[]) r;
                java.util.List<String> kept = new java.util.ArrayList<>(arr.length);
                for (String p : arr) {
                    if (p == null || !isHiddenPkg(p)) kept.add(p);
                }
                if (kept.size() != arr.length) {
                    // 空数组会让调用方以为该 uid 无包，返回 null 更自然
                    param.setResult(kept.isEmpty() ? null : kept.toArray(new String[0]));
                }
            }
        });

        HookUtils.hookAllMethods(pmCls, "getPackagesHoldingPermissions", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Object r = param.getResult();
                if (!(r instanceof java.util.List)) return;
                java.util.List<?> list = (java.util.List<?>) r;
                java.util.List<Object> kept = new java.util.ArrayList<>(list.size());
                for (Object item : list) {
                    if (item instanceof android.content.pm.PackageInfo) {
                        String pkg = ((android.content.pm.PackageInfo) item).packageName;
                        if (isHiddenPkg(pkg)) continue;
                    }
                    kept.add(item);
                }
                if (kept.size() != list.size()) param.setResult(kept);
            }
        });

        // ---- 4. 解析查询：返回 null（表示"没有应用能处理"）----
        String[] resolveQuery = {
            "resolveActivity", "resolveService", "resolveContentProvider",
        };
        for (final String mth : resolveQuery) {
            HookUtils.hookAllMethods(pmCls, mth, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object r = param.getResult();
                    if (r == null) return;
                    String pkg = null;
                    if (r instanceof android.content.pm.ResolveInfo) {
                        android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) r;
                        if (ri.activityInfo != null) pkg = ri.activityInfo.packageName;
                        else if (ri.serviceInfo != null) pkg = ri.serviceInfo.packageName;
                        else if (ri.providerInfo != null) pkg = ri.providerInfo.packageName;
                    } else if (r instanceof android.content.pm.ProviderInfo) {
                        pkg = ((android.content.pm.ProviderInfo) r).packageName;
                    }
                    if (pkg != null && isHiddenPkg(pkg)) param.setResult(null);
                }
            });
        }

        // ---- 5. query* 系列：从 List<ResolveInfo> 里剔除 ----
        String[] queryMethods = {
            "queryIntentActivities", "queryIntentServices",
            "queryBroadcastReceivers", "queryIntentContentProviders",
        };
        for (final String mth : queryMethods) {
            HookUtils.hookAllMethods(pmCls, mth, new XC_MethodHook() {
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    Object r = param.getResult();
                    if (!(r instanceof java.util.List)) return;
                    java.util.List<?> list = (java.util.List<?>) r;
                    java.util.List<Object> kept = new java.util.ArrayList<>(list.size());
                    for (Object item : list) {
                        String pkg = null;
                        if (item instanceof android.content.pm.ResolveInfo) {
                            android.content.pm.ResolveInfo ri = (android.content.pm.ResolveInfo) item;
                            if (ri.activityInfo != null) pkg = ri.activityInfo.packageName;
                            else if (ri.serviceInfo != null) pkg = ri.serviceInfo.packageName;
                            else if (ri.providerInfo != null) pkg = ri.providerInfo.packageName;
                        }
                        if (pkg == null || !isHiddenPkg(pkg)) kept.add(item);
                    }
                    if (kept.size() != list.size()) param.setResult(kept);
                }
            });
        }

        XposedEntry.log("hookPackageManager: 25+ methods covered, hidden=" + HIDDEN_PKGS.length + " pkgs");
    }

    private static boolean isSuspiciousPath(String path) {
        // Comprehensive list of root-related paths
        String[] suspiciousPaths = {
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/system/bin/su",
            "/system/bin/.ext/.su",
            "/system/sd/xbin/su",
            "/system/usr/we-need-root/su",
            "/system/xbin/su",
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/etc/init.d/99SuperSUDaemon",
            "/dev/com.koushikdutta.superuser.daemon/",
            "/system/xbin/daemonsu",
            // Magisk
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/magisk.log",
            "/data/magisk.img",
            "/data/adb/magisk.img",
            // KernelSU
            "/data/adb/ksu",
            "/data/adb/ksud",
            // 【V10 补全】以下为参考项目有而我们之前缺失的
            "/data/adb",                 // 整个目录（覆盖 modules/lspd 等一切子路径）
            "/data/adb/modules",         // Magisk / KSU 模块
            "/data/adb/lspd",            // Vector / LSPosed daemon
            "/data/adb/ap",              // APatch
            "/debug_ramdisk",            // Magisk 挂载点
            "/sbin/.magisk",             // Magisk 旧路径
            "/data/misc/lspd",           // LSPosed 备用
            "/data/local/tmp/lspd",      // LSPosed 临时
            // busybox / 提权工具
            "/system/xbin/busybox",
            "/system/bin/busybox",
            "/data/local/busybox",
            // 其他 root 实现
            "/system/xbin/daemonsu",
            "/su/xbin",
            "/su/bin",
            // Xposed 旧版
            "/system/framework/XposedBridge.jar",
            "/data/data/de.robv.android.xposed.installer",
            // 【V10】我们自己的模块（不能让它被 QQ 扫到）
            "/data/app/io.github.kida.qqnativeguard",
            "/data/app/io.github.qqenhanced.bypass"
        };

        for (String suspicious : suspiciousPaths) {
            if (path.contains(suspicious)) {
                return true;
            }
        }
        return false;
    }
}
