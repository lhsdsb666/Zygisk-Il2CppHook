// ============================================================
// 免 root 独立注入入口 —— 由重打包 APK 内的 HackProvider（ContentProvider）
// 在 Application 启动之前调用 System.loadLibrary("hack") 触发。
//
// 与 root/Zygisk 版的区别：
//   1. 不依赖 Zygisk：普通安装包即可运行，无需 KernelSU/Magisk。
//   2. ContentProvider.onCreate 早于 Application.onCreate —— Presto SDK 的
//      签名/完整性检测若在 Application 阶段自毁，exit blocker 已提前就位。
//   3. 翻译字典从 APK assets 首启释放到 GameDictPath（已存在则不覆盖，
//      保留玩家热更过的字典）。
//   4. 仅构建 arm64：游戏 split 为 arm64-only，x86 模拟器由 NativeBridge
//      自动转译加载 arm64 库（与游戏自身 libil2cpp.so 的加载方式相同）。
//
// 失败安全原则：本文件任何一步失败都只记日志，绝不阻止游戏启动。
// ============================================================

#include "hack.h"
#include "game.h"
#include "log.h"

#include <jni.h>
#include <thread>
#include <cstdio>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>

// 递归 mkdir（类似 mkdir -p），已存在的目录忽略 EEXIST
static void mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; ++p) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

// 取当前 Application 上下文（ContentProvider.onCreate 阶段 Application
// 对象已经 makeApplication 完成，currentApplication() 非空；仅 Application.onCreate
// 尚未调用，而这正是我们想要的"比 Presto 更早"的时机）。
// 调用方保证当前线程已 attached（JNI_OnLoad 回调线程必然已 attach）。
static jobject get_application(JNIEnv *env) {
    jclass at_clz = env->FindClass("android/app/ActivityThread");
    if (!at_clz) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    jmethodID cur_app = env->GetStaticMethodID(at_clz, "currentApplication",
                                               "()Landroid/app/Application;");
    if (!cur_app) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        return nullptr;
    }
    jobject app = env->CallStaticObjectMethod(at_clz, cur_app);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return nullptr;
    }
    return app;
}

// 把 APK assets/string_data.txt 释放到 GameDictPath（仅当目标不存在）。
// 失败只记日志：玩家仍可手动 adb push 字典到同一路径，热重载会自动加载。
static void extract_bundled_dict(JNIEnv *env) {
    if (access(GameDictPath, F_OK) == 0) {
        LOGI("【独立注入】字典已存在（%s），保留现有文件不覆盖。", GameDictPath);
        return;
    }

    jobject app = get_application(env);
    if (!app) {
        LOGE("【独立注入】取不到 Application，assets 字典释放跳过。");
        return;
    }

    jclass ctx_clz = env->FindClass("android/content/Context");
    jmethodID get_assets = env->GetMethodID(ctx_clz, "getAssets",
                                            "()Landroid/content/res/AssetManager;");
    if (!get_assets) {
        if (env->ExceptionCheck()) env->ExceptionClear();
        LOGE("【独立注入】找不到 getAssets 方法，字典释放跳过。");
        return;
    }
    jobject assets = env->CallObjectMethod(app, get_assets);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        LOGE("【独立注入】getAssets 调用异常，字典释放跳过。");
        return;
    }

    AAssetManager *mgr = AAssetManager_fromJava(env, assets);
    if (!mgr) {
        LOGE("【独立注入】AAssetManager_fromJava 返回空，字典释放跳过。");
        return;
    }
    AAsset *aa = AAssetManager_open(mgr, "string_data.txt", AASSET_MODE_BUFFER);
    if (!aa) {
        LOGI("【独立注入】APK assets 内无 string_data.txt，字典释放跳过。");
        return;
    }

    off_t len = AAsset_getLength(aa);
    const void *buf = AAsset_getBuffer(aa);
    if (len <= 0 || !buf) {
        LOGE("【独立注入】assets 字典读取失败（len=%ld）。", (long)len);
        AAsset_close(aa);
        return;
    }

    // 关键：Android 11+ 上 app 自己 mkdir /sdcard/Android/data/<pkg> 会被
    // FUSE 拒绝（EACCES），必须通过 Context.getExternalFilesDir(null) 让
    // 系统服务创建该目录（返回路径就是 GameDictPath 的父目录）。
    jmethodID get_efs = env->GetMethodID(ctx_clz, "getExternalFilesDir",
                                         "(Ljava/lang/String;)Ljava/io/File;");
    if (get_efs) {
        jobject efs = env->CallObjectMethod(app, get_efs, (jstring) nullptr);
        if (env->ExceptionCheck()) env->ExceptionClear();
        if (efs) LOGI("【独立注入】外部 files 目录已就绪。");
    }

    // 兜底：再 mkdir -p 一次（旧系统或内部目录场景）
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", GameDictPath);
    char *slash = strrchr(dir, '/');
    if (slash) {
        *slash = 0;
        mkdir_p(dir);
    }

    FILE *f = fopen(GameDictPath, "wb");
    if (!f) {
        LOGE("【独立注入】无法写入 %s，字典释放跳过。", GameDictPath);
        AAsset_close(aa);
        return;
    }
    size_t written = fwrite(buf, 1, (size_t)len, f);
    fclose(f);
    AAsset_close(aa);
    LOGI("【独立注入】内置字典已释放：%s（%ld 字节写入 %zu）。",
         GameDictPath, (long)len, written);
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    // ① 最早时机拦截自毁：Presto 的签名/完整性检测失败时会
    //    exit()/kill(getpid(), SIGKILL)，此处先于 Application 初始化把
    //    libc 的 exit/_exit/kill/tgkill 全部 hook 掉。
    hook_exit_functions();
    LOGI("【独立注入】libhack.so JNI_OnLoad：exit/kill blocker 已提前激活。");

    // ② 释放内置字典到 files 目录（JNI_OnLoad 回调线程已 attach）
    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **) &env, JNI_VERSION_1_6) == JNI_OK && env) {
        extract_bundled_dict(env);
    } else {
        LOGE("【独立注入】GetEnv 失败，assets 字典释放跳过。");
    }

    // ③ 起翻译线程：hack_start 内部自行轮询等待 libil2cpp.so 加载
    //    （最长 300 秒），所以现在起线程时机安全。game_data_dir 在
    //    hack_start 内未实际使用，传 nullptr。
    std::thread([] {
        LOGI("【独立注入】hack_start 工作线程启动，等待游戏运行时就绪...");
        hack_start(nullptr);
    }).detach();

    return JNI_VERSION_1_6;
}
