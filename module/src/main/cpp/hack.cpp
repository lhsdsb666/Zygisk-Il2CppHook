//
// Created by Perfare on 2020/7/4.
// 彻底修复闪退与全局解耦进化版 (寄存器对齐修正版)
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
#include <unordered_map> 

extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// ==================== Unity 底层字符串结构与 API 定义 ====================
struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0]; 
};

typedef MyIl2CppString* (*il2cpp_string_new_ptr)(const char* text);
static il2cpp_string_new_ptr il2cpp_string_new = nullptr;
static void* china_font_asset_ptr = nullptr;

typedef void* (*il2cpp_object_get_class_fn)(void* obj);
typedef void* (*il2cpp_class_get_field_from_name_fn)(void* klass, const char* name);
typedef void (*il2cpp_field_set_value_fn)(void* obj, void* field, void** value);
typedef void (*il2cpp_field_get_value_fn)(void* obj, void* field, void* value); 
typedef const char* (*il2cpp_class_get_name_fn)(void* klass);
typedef void* (*il2cpp_class_get_parent_fn)(void* klass); 

static il2cpp_object_get_class_fn il2cpp_object_get_class = nullptr;
static il2cpp_class_get_field_from_name_fn il2cpp_class_get_field_from_name = nullptr;
static il2cpp_field_set_value_fn il2cpp_field_set_value = nullptr;
static il2cpp_field_get_value_fn il2cpp_field_get_value = nullptr; 
static il2cpp_class_get_name_fn il2cpp_class_get_name = nullptr;
static il2cpp_class_get_parent_fn il2cpp_class_get_parent = nullptr; 

typedef void* (*AssetBundle_LoadFromFile_t)(MyIl2CppString* path);
typedef void* (*AssetBundle_LoadAsset_t)(void* __this, MyIl2CppString* name, void* method_info);

static AssetBundle_LoadFromFile_t Unity_LoadFromFile = nullptr;
static AssetBundle_LoadAsset_t Unity_LoadAsset = nullptr;

// ==================== 简易汉化字典 ====================
static const std::unordered_map<std::string, std::string> translation_dict = {
    {"상점", "商店"},
    {"친구", "好友"},
    {"이벤트 팝업", "活动"},
    {"레벨 패스", "等级通行证"},
    {"BETA", "测试版"}
};

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
            utf8 += (char)(0x80 | ((cp >> 12) & 0x3f));
            utf8 += (char)(0x80 | ((cp >> 6) & 0x3f));
            utf8 += (char)(0x80 | (cp & 0x3f));
        }
    }
    return utf8;
}

std::string get_module_path_and_base(const char* module_name, uintptr_t& out_base) {
    out_base = 0;
    char line[512];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp != nullptr) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name) != nullptr) {
                if (out_base == 0) {
                    out_base = strtoul(line, nullptr, 16);
                }
                char* path_start = strchr(line, '/');
                if (path_start) {
                    std::string path(path_start);
                    while (!path.empty() && (path.back() == '\n' || path.back() == '\r' || path.back() == ' ')) {
                        path.pop_back();
                    }
                    fclose(fp);
                    return path;
                }
            }
        }
        fclose(fp);
    }
    return "";
}

// ==================== Hook 退出函数 ====================
static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;

void my_exit(int status) {
    LOGI("[HACK_BYPASS] Blocked exit(%d)", status);
    while (true) { sleep(3600); }
}
void my__exit(int status) {
    LOGI("[HACK_BYPASS] Blocked _exit(%d)", status);
    while (true) { sleep(3600); }
}

void hook_exit_functions() {
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc != nullptr) {
        void* exit_sym = dlsym(libc, "exit");
        if (exit_sym) DobbyHook(exit_sym, (void*)my_exit, (void**)&old_exit);
        void* _exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) DobbyHook(_exit_sym, (void*)my__exit, (void**)&old__exit);
    }
}

// ==================== 字段搜索器 ====================
void* find_field_in_hierarchy(void* klass, const char* field_name) {
    void* field = nullptr;
    while (klass != nullptr) {
        if (il2cpp_class_get_field_from_name) {
            field = il2cpp_class_get_field_from_name(klass, field_name);
            if (field != nullptr) return field; 
        }
        if (il2cpp_class_get_parent) {
            klass = il2cpp_class_get_parent(klass); 
        } else {
            break;
        }
    }
    return nullptr;
}

// ==================== 字体加载（大幅延迟版） ====================
static bool g_font_loaded = false;
void load_chinese_font_asset(uintptr_t il2cpp_base) {
    if (g_font_loaded) return;
    g_font_loaded = true;

    LOGI("[HACK_FONT] Starting font load (delayed)...");
    sleep(8);   // 大幅增加延迟，让logo和初始界面加载完

    if (!il2cpp_string_new) {
        LOGE("[HACK_FONT] il2cpp_string_new is NULL!");
        return;
    }

    Unity_LoadFromFile = (AssetBundle_LoadFromFile_t)(il2cpp_base + 0xb64fe38);
    Unity_LoadAsset = (AssetBundle_LoadAsset_t)(il2cpp_base + 0xb650040);

    const char* path = "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans";

    void* font_bundle = Unity_LoadFromFile(il2cpp_string_new(path));
    if (!font_bundle) {
        LOGE("[HACK_FONT] Failed to load font file!");
        return;
    }

    LOGI("[HACK_FONT] AssetBundle loaded!");

    const char* names[] = {"zh-hans", "ZH-HANS", "SystemFont", "font", "zh_hans"};
    for (int i = 0; i < 5; i++) {
        china_font_asset_ptr = Unity_LoadAsset(font_bundle, il2cpp_string_new(names[i]), nullptr);
        if (china_font_asset_ptr) {
            LOGI("[HACK_FONT] SUCCESS: Chinese Font Loaded! Name: %s, Ptr: %p", names[i], china_font_asset_ptr);
            return;
        }
    }
    LOGE("[HACK_FONT] Failed to load asset");
}

// ==================== TextMeshPro Hook ====================
static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    if (!g_font_loaded) {
        uintptr_t base = 0;
        get_module_path_and_base("libil2cpp.so", base);
        if (base != 0) load_chinese_font_asset(base);
    }

    MyIl2CppString* final_string = il2cpp_string;

    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string origin_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
        auto it = translation_dict.find(origin_text);
        if (it != translation_dict.end()) {
            final_string = il2cpp_string_new(it->second.c_str());
        }
    }

    if (china_font_asset_ptr != nullptr && __this != nullptr && il2cpp_object_get_class && il2cpp_field_set_value) {
        void* text_klass = il2cpp_object_get_class(__this);
        if (text_klass) {
            void* font_field = find_field_in_hierarchy(text_klass, "m_fontAsset");
            if (font_field) {
                il2cpp_field_set_value(__this, font_field, &china_font_asset_ptr);
            }
        }
    }

    old_set_text(__this, final_string);
}

// ==================== 核心启动器 ====================
void hack_start(const char *game_data_dir) {
    LOGI("[HACK_INIT] hack_start initiated.");
    hook_exit_functions(); 

    uintptr_t il2cpp_base = 0;
    for (int i = 0; i < 300; i++) {
        std::string real_path = get_module_path_and_base("libil2cpp.so", il2cpp_base);
        
        if (!real_path.empty() && il2cpp_base != 0) {
            void *handle = xdl_open(real_path.c_str(), 0); 
            if (!handle) handle = xdl_open("libil2cpp.so", 0);      
            if (!handle) handle = dlopen(real_path.c_str(), RTLD_LAZY); 

            if (handle) {
                LOGI("[HACK_INIT] libil2cpp.so bound successfully.");
                
                auto find_sym = [](void* h, const char* name) -> void* {
                    void* sym = xdl_sym(h, name, nullptr);
                    if (!sym) sym = dlsym(h, name);
                    return sym;
                };

                il2cpp_string_new = (il2cpp_string_new_ptr)find_sym(handle, "il2cpp_string_new");
                il2cpp_object_get_class = (il2cpp_object_get_class_fn)find_sym(handle, "il2cpp_object_get_class");
                il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_fn)find_sym(handle, "il2cpp_class_get_field_from_name");
                il2cpp_field_set_value = (il2cpp_field_set_value_fn)find_sym(handle, "il2cpp_field_set_value");
                il2cpp_field_get_value = (il2cpp_field_get_value_fn)find_sym(handle, "il2cpp_field_get_value"); 
                il2cpp_class_get_name = (il2cpp_class_get_name_fn)find_sym(handle, "il2cpp_class_get_name");
                il2cpp_class_get_parent = (il2cpp_class_get_parent_fn)find_sym(handle, "il2cpp_class_get_parent"); 

                void* set_text_addr = (void*)(il2cpp_base + 0xb5b099c);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("[HACK_INIT] Hook deployed successfully.");
                
                break;
            }
        }
        sleep(1);
    }
}

// ==================== 原封不动的底层代码 ====================
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
    uint32_t version; void *initialize;
    void *(*loadLibrary)(const char *libpath, int flag);
    void *(*getTrampoline)(void *handle, const char *name, const char *shorty, uint32_t len);
    void *isSupported; void *getAppEnv; void *isCompatibleWith; void *getSignalHandler;
    void *unloadLibrary; void *getError; void *isPathSupported; void *initAnonymousNamespace;
    void *createNamespace; void *linkNamespaces;
    void *(*loadLibraryExt)(const char *libpath, int flag, void *ns);
};

bool NativeBridgeLoad(const char *game_data_dir, int api_level, void *data, size_t length) {
    sleep(5);
    auto libart = dlopen("libart.so", RTLD_NOW);
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *)) dlsym(libart, "JNI_GetCreatedJavaVMs");
    JavaVM *vms_buf[1]; JavaVM *vms; jsize num_vms;
    jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
    if (status == JNI_OK && num_vms > 0) { vms = vms_buf[0]; } else { return false; }
    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) { munmap(data, length); return false; }
    auto nb = dlopen("libhoudini.so", RTLD_NOW);
    if (!nb) { auto native_bridge = GetNativeBridgeLibrary(); nb = dlopen(native_bridge.data(), RTLD_NOW); }
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
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif