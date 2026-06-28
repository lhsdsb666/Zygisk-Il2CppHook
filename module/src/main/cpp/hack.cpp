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
#include <cstdint> 
#include <string>  

// ===== 核心黑科技：直接前置声明 Dobby 函数 =====
extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// ==================== 获取模块基地址 ====================
uintptr_t get_module_base(const char* module_name) {
    uintptr_t base = 0;
    char line[512];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp != nullptr) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name) != nullptr) {
                base = strtoul(line, nullptr, 16);
                break;
            }
        }
        fclose(fp);
    }
    return base;
}

// ==================== Hook 退出函数（防自杀） ====================
static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;
static void (*old_abort)() = nullptr;

void my_exit(int status) {
    LOGI("【Hook】Blocked exit(%d) !", status);
    while (true) { sleep(3600); }
}

void my__exit(int status) {
    LOGI("【Hook】Blocked _exit(%d) !", status);
    while (true) { sleep(3600); }
}

void my_abort() {
    LOGI("【Hook】Blocked abort() !");
    while (true) { sleep(3600); }
}

void hook_exit_functions() {
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc != nullptr) {
        void* exit_sym = dlsym(libc, "exit");
        if (exit_sym) {
            DobbyHook(exit_sym, (void*)my_exit, (void**)&old_exit);
            LOGI("Hooked exit() at %p", exit_sym);
        }
        void* _exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) {
            DobbyHook(_exit_sym, (void*)my__exit, (void**)&old__exit);
            LOGI("Hooked _exit() at %p", _exit_sym);
        }
    }
    void* abort_sym = dlsym(RTLD_DEFAULT, "abort");
    if (abort_sym) {
        DobbyHook(abort_sym, (void*)my_abort, (void**)&old_abort);
        LOGI("Hooked abort() at %p", abort_sym);
    }
    LOGI("【Hook】Exit functions hooked successfully");
}

// ==================== TextMeshPro 文本拦截器 ====================
struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0]; 
};

// UTF-16 转 UTF-8
std::string utf16_to_utf8(const char16_t* utf16, int len) {
    std::string utf8;
    for (int i = 0; i < len; ++i) {
        unsigned long cp = utf16[i];
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < len) {
            unsigned long trail = utf16[i + 1];
            if (trail >= 0xdc00 && trail <= 0xdfff) {
                cp = (cp - 0xd800) << 10 | (trail - 0xdc00);
                cp += 0x10000;
                i++;
            }
        }
        if (cp <= 0x7f) utf8 += (char)cp;
        else if (cp <= 0x7ff) {
            utf8 += (char)(0xc0 | (cp >> 6));
            utf8 += (char)(0x80 | (cp & 0x3f));
        } else if (cp <= 0xffff) {
            utf8 += (char)(0xe0 | (cp >> 12));
            utf8 += (char)(0x80 | ((cp >> 6) & 0x3f));
            utf8 += (char)(0x80 | (cp & 0x3f));
        } else {
            utf8 += (char)(0xf0 | (cp >> 18));
            utf8 += (char)(0x80 | ((std::uintptr_t)(cp >> 12) & 0x3f));
            utf8 += (char)(0x80 | ((cp >> 6) & 0x3f));
            utf8 += (char)(0x80 | (cp & 0x3f));
        }
    }
    return utf8;
}

static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    // 【核心改动 1】：无条件绝对打印！只要进这个函数，CMD 必须弹字
    LOGI("【🔥触发成功】my_set_text 正在执行！__this: %p | string_ptr: %p", __this, il2cpp_string);
    
    if (il2cpp_string != nullptr) {
        // 【核心改动 2】：哪怕长度是 0 或者负数（异常值），我们也打印出来看看到底是多少
        LOGI("【数据测试】当前获取到的字符串内部长度为: %d", il2cpp_string->length);
        
        if (il2cpp_string->length > 0) {
            std::string text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
            // 目标刷屏打印
            LOGI("【💥文本拦截】内容: %s", text.c_str());
        }
    }
    
    // 放行
    old_set_text(__this, il2cpp_string);
}


void hack_start(const char *game_data_dir) {
    bool load = false;
    LOGI("hack_start started, waiting for libil2cpp.so...");

    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            LOGI("Found libil2cpp.so! Starting hooks...");

            hook_exit_functions();

            uintptr_t il2cpp_base = get_module_base("libil2cpp.so");
            if (il2cpp_base != 0) {
                LOGI("【成功】安全获取到 il2cpp 基地址: 0x%llx", (unsigned long long)il2cpp_base);
                
                // 挂钩目标 RVA 基地址 0xb5b099c
                void* set_text_addr = (void*)(il2cpp_base + 0xb5b099c);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】TextMeshPro::set_text 挂钩完成！地址: %p", set_text_addr);
            } else {
                LOGE("【失败】未能获取到 il2cpp 基地址");
            }
            break;
        } else {
            sleep(1);
        }
    }
    
    if (!load) {
        LOGI("libil2cpp.so not found in thread %d", gettid());
    }
}

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
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
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
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
    uint32_t version;
    void *initialize;
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported;
    void *getAppEnv;
    void *isCompatibleWith;
    void *getSignalHandler;
    void *unloadLibrary;
    void *getError;
    void *isPathSupported;
    void *initAnonymousNamespace;
    void *createNamespace;
    void *linkNamespaces;
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1];
    JavaVM *vms;
    jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) { vms = vms_buf[0]; } else { return false; }

    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) { munmap(data, length); return false; }

    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) {
        auto native_bridge = GetNativeBridgeLibrary();
        nb = dlopen(native_bridge.data(), RTLD_NOW);
    }
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
            ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
            memcpy(mem, data, length);
            munmap(mem, length);
            munmap(data, length);
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);

            void *arm_handle;
            if (api_level >= 26) { arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *) 3); } 
            else { arm_handle = callbacks->loadLibrary(path, RTLD_NOW); }
            
            if (arm_handle) {
                auto init = (void (*)(JavaVM *, void *)) callbacks->getTrampoline(arm_handle, "JNI_OnLoad", nullptr, 0);
                init(vms, (void *) game_data_dir);
                return true;
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
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
