//
// 终极汉化双挂载版 - 带日志监控与中文字典测试
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
#include <cstdint> 
#include <string>  

extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// Unity 底层字符串结构
struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0]; 
};

// 工具函数：将 Unity 的 UTF-16 文本安全转换成 UTF-8 用于 CMD 日志打印
std::string utf16_to_utf8(const char16_t* str, int len) {
    std::string utf8;
    for (int i = 0; i < len; ++i) {
        uint32_t cp = str[i];
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < len) {
            uint32_t trail = str[i + 1];
            if (trail >= 0xDC00 && trail <= 0xDFFF) {
                cp = ((cp - 0xD800) << 10) + (trail - 0xDC00) + 0x10000;
                ++i;
            }
        }
        if (cp <= 0x7F) { utf8 += (char)cp; } 
        else if (cp <= 0x7FF) { utf8 += (char)(0xC0 | ((cp >> 6) & 0x1F)); utf8 += (char)(0x80 | (cp & 0x3F)); } 
        else if (cp <= 0xFFFF) { utf8 += (char)(0xE0 | ((cp >> 12) & 0x0F)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3F)); utf8 += (char)(0x80 | (cp & 0x3F)); } 
        else { utf8 += (char)(0xF0 | ((cp >> 18) & 0x07)); utf8 += (char)(0x80 | ((cp >> 12) & 0x3F)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3F)); utf8 += (char)(0x80 | (cp & 0x3F)); }
    }
    return utf8;
}

// 核心汉化字典过滤器
void process_text_translation(MyIl2CppString* il2cpp_string) {
    if (il2cpp_string == nullptr || il2cpp_string->length <= 0) return;

    // 转换成标准字符串用于比对和打日志
    std::string original_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
    bool translated = false;
    std::string target_text = "";

    // 【测试字典】原地安全汉化替换（长度需要严格对齐以保障内存绝对安全）
    if (original_text == "모험") {          // 主界面：冒险
        il2cpp_string->chars[0] = 0x5192; // 冒
        il2cpp_string->chars[1] = 0x9669; // 险
        target_text = "冒险"; translated = true;
    } else if (original_text == "모집") {   // 主界面：招募
        il2cpp_string->chars[0] = 0x62DB; // 招
        il2cpp_string->chars[1] = 0x5E55; // 募
        target_text = "招募"; translated = true;
    } else if (original_text == "카드") {   // 主界面：卡牌
        il2cpp_string->chars[0] = 0x5361; // 卡
        il2cpp_string->chars[1] = 0x724C; // 牌
        target_text = "卡牌"; translated = true;
    }

    // 打印到电脑 CMD 的日志输出控制
    if (translated) {
        LOGI("[HACK_INIT] 【成功汉化】 %s -> %s", original_text.data(), target_text.data());
    } else {
        // 如果不是上面三个词，且包含韩文，就打印未翻译报告
        bool has_korean = false;
        for (int i = 0; i < il2cpp_string->length; i++) {
            char16_t c = il2cpp_string->chars[i];
            if ((c >= 0xAC00 && c <= 0xD7A3) || (c >= 0x1100 && c <= 0x11FF) || (c >= 0x3130 && c <= 0x318F)) {
                has_korean = true; break;
            }
        }
        if (has_korean) {
            LOGI("[HACK_INIT] 【未翻译文本】内容: %s", original_text.data());
        }
    }
}

// 两个不同渲染入口的拦截器
static void (*old_set_text_prop)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;
static void (*old_SetText_method)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text_prop(void* __this, MyIl2CppString* il2cpp_string) {
    process_text_translation(il2cpp_string);
    old_set_text_prop(__this, il2cpp_string);
}

void my_SetText_method(void* __this, MyIl2CppString* il2cpp_string) {
    process_text_translation(il2cpp_string);
    old_SetText_method(__this, il2cpp_string);
}

// 获取模块基址
std::string get_module_path_and_base(const char* module_name, uintptr_t& out_base) {
    out_base = 0;
    char line[512];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp != nullptr) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name) != nullptr) {
                if (out_base == 0) { out_base = strtoul(line, nullptr, 16); }
                char* path_start = strchr(line, '/');
                if (path_start) {
                    std::string path(path_start);
                    while (!path.empty() && (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) { path.pop_back(); }
                    fclose(fp); return path;
                }
            }
        }
        fclose(fp);
    }
    return "";
}

// 核心启动器
void hack_start(const char *game_data_dir) {
    (void)game_data_dir; 
    LOGI("[HACK_INIT] hack_start initiated.");

    uintptr_t il2cpp_base = 0;
    for (int i = 0; i < 300; i++) {
        std::string real_path = get_module_path_and_base("libil2cpp.so", il2cpp_base);
        
        if (!real_path.empty() && il2cpp_base != 0) {
            LOGI("[HACK_INIT] libil2cpp.so bound successfully.");

            // 通道 1：挂载小写属性 setter (0xb5b099c) -> 阻击大部分大厅静态 UI
            void* prop_addr = (void*)(il2cpp_base + 0xb5b099c);
            DobbyHook(prop_addr, (void*)my_set_text_prop, (void**)&old_set_text_prop);

            // 通道 2：挂载大写标准方法 (0xb5b5760) -> 阻击动态刷新文本
            void* method_addr = (void*)(il2cpp_base + 0xb5b5760);
            DobbyHook(method_addr, (void*)my_SetText_method, (void**)&old_SetText_method);

            LOGI("[HACK_INIT] Dual-Channel Hook deployed successfully.");
            break;
        }
        sleep(1);
    }
}

// ==================== 模拟器环境底层适配 ====================
std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr; vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz, currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz, "getApplicationInfo", "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application, get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(env->GetObjectClass(application_info), "nativeLibraryDir", "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        std::string lib_dir(path); env->ReleaseStringUTFChars(native_library_dir_jstring, path); return lib_dir;
                    }
                }
            }
        }
    }
    return {};
}

static std::string GetNativeBridgeLibrary() {
    auto value = std::array<char, PROP_VALUE_MAX>();
    __system_property_get("ro.dalvik.vm.native.bridge", value.data());
    return {value.data()};
}

struct NativeBridgeCallbacks {
    uint32_t version; void *initialize; void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported; void *getAppEnv; void *isCompatibleWith; void *getSignalHandler;
    void *unloadLibrary; void *getError; void *isPathSupported; void *initAnonymousNamespace;
    void *createNamespace; void *linkNamespaces; void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    sleep(5); auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1]; JavaVM *vms; jsize num_vms; jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) { vms = vms_buf[0]; } else { return false; }
    auto lib_dir = GetLibDir(vms); if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) { munmap(data, length); return false; }
    auto nb = dlopen("libhoudini.so", RTLD_NOW); if (!nb) { auto native_bridge = GetNativeBridgeLibrary(); nb = dlopen(native_bridge.data(), RTLD_NOW); }
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC); ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0); memcpy(mem, data, length); munmap(mem, length); munmap(data, length);
            char path[PATH_MAX]; snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
            void *arm_handle = (api_level >= 26) ? callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3) : callbacks->loadLibrary(path, RTLD_NOW);
            if (arm_handle) {
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                init(vms, (void *) game_data_dir); return true;
            }
            close(fd);
        }
    }
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    int api_level = android_get_device_api_level();
#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
#endif
        hack_start(game_data_dir);
#if defined(__i386__) || defined(__x86_64__)
    }
#endif
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *) reserved;
    std::thread hack_thread(hack_start, game_data_dir);   hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
