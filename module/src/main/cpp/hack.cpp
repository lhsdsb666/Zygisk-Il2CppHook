#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <thread>
#include <xdl.h>
#include <dlfcn.h>   // 👈 必须引入！否则 Dl_info 和 dladdr 会报错
#include "dobby.h"

#define LOGTAG "汉化日志"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOGTAG, __VA_ARGS__)

// ==========================================
// 1. 全局变量与 Hook 函数声明（让编译器认识它们）
// ==========================================
uintptr_t il2cpp_base = 0; // 用来存游戏基地址

// 假设的原函数指针（先用 void* 占位，保证编译通过。后面可以根据 dump.cs 调整参数）
void *(*old_set_text)(void *instance, void *str) = nullptr;

// 你自己的替换函数（拦截韩文的核心舞台）
void *my_set_text(void *instance, void *str) {
    // 【前期测试】先直接放行调用原函数，保证游戏绝对不卡死、不闪退
    // 后面咱们就在这里拦截 str 并替换成中文
    return old_set_text(instance, str);
}

// ==========================================
// 2. 专属 Hook 集中营
// ==========================================
void il2cpp_hook() {
    if (il2cpp_base == 0) {
        LOGI("【核心错误】基地址为 0，无法执行 Hook！");
        return;
    }

    // 计算你要狙击的绝对地址（基址 + 偏移量）
    uintptr_t target_addr = il2cpp_base + 0xb5b099c; 

    // 让 Dobby 开始挂钩
    DobbyHook((void*)target_addr, (void*)my_set_text, (void**)&old_set_text);
    LOGI("【汉化日志】狙击手已在绝对地址 %p 就位！", (void*)target_addr);
}

// ==========================================
// 3. 核心启动器（负责后台死等 .so 落地）
// ==========================================
void hack_start(const char *game_data_dir) {
    bool load = false;
    
    // 允许在后台死等 300 秒（5分钟）
    for (int i = 0; i < 300; i++) { 
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            
            // 1. 初始化模板自带的 API
            // il2cpp_api_init(handle); 

            LOGI("【汉化日志】libil2cpp.so 已加载，开始计算绝对地址...");
            
            // 2. 动态获取当前运行时的游戏基地址
            void *il2cpp_init_addr = xdl_sym(handle, "il2cpp_init", nullptr);
            if (il2cpp_init_addr) {
                Dl_info info;
                if (dladdr(il2cpp_init_addr, &info)) {
                    il2cpp_base = (uintptr_t)info.dli_fbase;
                    LOGI("【汉化日志】成功获取到游戏基地址: %p", (void*)il2cpp_base);
                }
            }
            
            // 3. 基础准备完毕，去执行真正的 Hook 挂钩
            il2cpp_hook();
            break;
        } else {
            // 没找到就每秒探查一次
            sleep(1); 
        }
    }
    
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}
