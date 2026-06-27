//
// Created by Perfare on 2020/7/4.
// 纯净精简版 - 全局韩文强制变方块测试版
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
typedef void (*il2cpp_field_set_value_fn)(void* obj, void* field, void* value);
typedef const char* (*il2cpp_class_get_name_fn)(void* klass);
typedef void* (*il2cpp_class_get_parent_fn)(void* klass); 

static il2cpp_object_get_class_fn il2cpp_object_get_class = nullptr;
static il2cpp_class_get_field_from_name_fn il2cpp_class_get_field_from_name = nullptr;
static il2cpp_field_set_value_fn il2cpp_field_set_value = nullptr;
static il2cpp_class_get_name_fn il2cpp_class_get_name = nullptr;
static il2cpp_class_get_parent_fn il2cpp_class_get_parent = nullptr; 

// 严格恢复 Unity 底层标准参数签名，防止寄存器污染导致闪退
typedef void* (*AssetBundle_LoadFromFile_t)(MyIl2CppString* path, uint32_t crc, uint64_t offset);
typedef void* (*AssetBundle_LoadAllAssets_t)(void* bundle, void* type);

static AssetBundle_LoadFromFile_t Unity_LoadFromFile = nullptr;
static AssetBundle_LoadAllAssets_t Unity_LoadAllAssets = nullptr;

// ==================== 获取模块基址 ====================
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

// ==================== 核心字库唤醒（精准绝对地址修复版） ====================
static bool g_font_loaded = false;
void load_chinese_font_asset(uintptr_t il2cpp_base) {
    if (g_font_loaded) return;
    LOGI("[HACK_FONT] Entering load_chinese_font_asset...");

    if (!il2cpp_string_new) {
        LOGE("[HACK_FONT] ERROR: il2cpp_string_new is NULL!");
        g_font_loaded = true;
        return;
    }

    // 绑定精准匹配的 RVA 偏移量
    Unity_LoadFromFile = (AssetBundle_LoadFromFile_t)(il2cpp_base + 0xb64fe38);
    Unity_LoadAllAssets = (AssetBundle_LoadAllAssets_t)(il2cpp_base + 0xb65077c);

    // 默认读取外置存储中的字库包文件（请确保 9.17MB 的字库文件已重命名为 zh-hans 放在此目录下）
    const char* path_external = "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans";
    
    LOGI("[HACK_FONT] Loading AssetBundle via Hardcoded RVA...");
    // 修复：传入 3 个参数 (路径, CRC=0, 偏移量=0) 确保不闪退
    void* font_bundle = Unity_LoadFromFile(il2cpp_string_new(path_external), 0, 0);

    if (font_bundle) {
        LOGI("[HACK_FONT] AssetBundle loaded successfully! Extracting font asset...");
        // 修复：传入 2 个参数 确保不闪退
        void* assets_array = Unity_LoadAllAssets(font_bundle, nullptr);
        if (assets_array) {
            int32_t array_length = *(int32_t*)((uintptr_t)assets_array + 0x18);
            LOGI("[HACK_FONT] Found %d assets in bundle.", array_length);
            if (array_length <= 0 || array_length > 100) array_length = 10; 

            for (int i = 0; i < array_length; i++) {
                void* test_ptr = ((void**)assets_array)[4 + i];
                if (test_ptr && il2cpp_object_get_class && il2cpp_class_get_name) {
                    if ((uintptr_t)test_ptr < 0x100000) continue; 
                    
                    void* klass = il2cpp_object_get_class(test_ptr);
                    if (!klass) continue;
                    const char* class_name = il2cpp_class_get_name(klass);
                    
                    if (class_name && (strstr(class_name, "FontAsset") != nullptr || strstr(class_name, "TMP_Font") != nullptr)) {
                        china_font_asset_ptr = test_ptr;
                        LOGI("[HACK_FONT] SUCCESS: Target font intercepted! Ptr: %p", china_font_asset_ptr);
                        break; 
                    }
                }
            }
        }
    } else {
        LOGE("[HACK_FONT] CRITICAL: Cannot open font file 'zh-hans' from path!");
    }
    g_font_loaded = true;
}

// ==================== TextMeshPro 文本拦截器（方块字强推机） ====================
static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    // 核心逻辑：只要外置字库加载成功，直接把每一个文本组件的主字体全部替换掉
    // 因为外置字库里没有韩文字形，这样游戏里的韩文就会因为找不到字形全部自动安全地变成 [□] 豆腐块！
    if (china_font_asset_ptr != nullptr && __this != nullptr && il2cpp_object_get_class) {
        void* text_klass = il2cpp_object_get_class(__this);
        if (text_klass) {
            void* font_field = find_field_in_hierarchy(text_klass, "m_fontAsset");
            if (font_field && il2cpp_field_set_value) {
                il2cpp_field_set_value(__this, font_field, &china_font_asset_ptr);
            }
        }
    }
    old_set_text(__this, il2cpp_string);
}

// ==================== 核心启动器 ====================
void hack_start(const char *game_data_dir) {
    (void)game_data_dir; // 压制 GitHub CI 未使用变量警告
    LOGI("[HACK_INIT] hack_start initiated.");

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
                il2cpp_class_get_name = (il2cpp_class_get_name_fn)find_sym(handle, "il2cpp_class_get_name");
                il2cpp_class_get_parent = (il2cpp_class_get_parent_fn)find_sym(handle, "il2cpp_class_get_parent"); 

                // 挂载文本渲染 Hook
                void* set_text_addr = (void*)(il2cpp_base + 0xb5b099c);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("[HACK_INIT] Hook deployed successfully.");
                
                // 加载外置字库并强制触发方块字测试
                load_chinese_font_asset(il2cpp_base);
                break;
            }
        }
        sleep(1);
    }
}

// ==================== 模拟器环境底层适配与桥接代码（不可删除） ====================
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
