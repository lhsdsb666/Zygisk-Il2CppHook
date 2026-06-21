//
// Created by Perfare on 2020/7/4.
//

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <sys/system_properties.h>
#include <dlfcn.h>
#include <jni.h>
#include <thread>
#include <sys/mman.h>
#include <linux/unistd.h>
#include <array>

// ==================== 加强版 Hook 退出函数 ====================
static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;
static void (*old_abort)() = nullptr;

void my_exit(int status) {
    LOGI("【ANTI-CRASH】Blocked exit(%d) ! 阻止自杀", status);
    return;
}

void my__exit(int status) {
    LOGI("【ANTI-CRASH】Blocked _exit(%d) ! 阻止自杀", status);
    return;
}

void my_abort() {
    LOGI("【ANTI-CRASH】Blocked abort() ! 阻止自杀");
    return;
}

void hook_exit_functions(void* handle) {
    LOGI("【ANTI-CRASH】Starting exit hook...");

    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc) {
        void* exit_sym = dlsym(libc, "exit");
        if (exit_sym) {
            old_exit = (void(*)(int))exit_sym;
            LOGI("Found exit() at %p", exit_sym);
        }

        void* _exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) {
            old__exit = (void(*)(int))_exit_sym;
            LOGI("Found _exit() at %p", _exit_sym);
        }
    }

    void* abort_sym = dlsym(RTLD_DEFAULT, "abort");
    if (abort_sym) {
        old_abort = (void(*)())abort_sym;
        LOGI("Found abort() at %p", abort_sym);
    }

    LOGI("【ANTI-CRASH】Exit hook setup completed");
}
// ========================================================

void hack_start(const char *game_data_dir) {
    bool load = false;
    LOGI("hack_start started, waiting for libil2cpp.so...");

    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            LOGI("✅ Found libil2cpp.so!");

            // 先 Hook 退出函数
            hook_exit_functions(handle);

            il2cpp_api_init(handle);
            il2cpp_hook();
            break;
        } else {
            if (i % 30 == 0) LOGI("Waiting... %d/300", i);
            sleep(1);
        }
    }
    
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}

// 下面 GetLibDir、NativeBridgeLoad、hack_prepare、JNI_OnLoad 保持不变
std::string GetLibDir(JavaVM *vms) { ... }   // 保持你原来的代码

// ...（NativeBridgeLoad、hack_prepare、JNI_OnLoad 部分请保持你文件里原来的代码不变）
