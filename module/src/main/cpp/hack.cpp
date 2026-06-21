#include <unistd.h>
#include <thread>
#include <xdl.h>
#include <android/log.h>

#define LOG_TAG "ZygiskIl2CppHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)

// 📢 注意：这两个是模板自带的，声明在这里就行，千万不要在下面重写它们！
void il2cpp_api_init(void *handle);
void il2cpp_hook();

void hack_start(const char *game_data_dir) {
    bool load = false;
    
    // 🛠️ 纯净修改：只把原本的 10 改成了 300，让它在后台死等 5 分钟
    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            LOGI("【汉化日志】终于等到 libil2cpp.so 加载了！开始交接任务...");
            
            // 执行模板原本的初始化和 Hook 流程
            il2cpp_api_init(handle);
            il2cpp_hook(); 
            break;
        } else {
            sleep(1);
        }
    }
    
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}
