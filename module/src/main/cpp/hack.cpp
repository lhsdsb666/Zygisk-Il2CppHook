// ===== 带有全量内存雷达诊断的 hack.cpp =====
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

struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0]; 
};

typedef MyIl2CppString* (*il2cpp_string_new_ptr)(const char* text);
static il2cpp_string_new_ptr il2cpp_string_new = nullptr;
static void* china_font_asset_ptr = nullptr;

typedef void* (*il2cpp_resolve_icall_fn)(const char* name);
typedef void* (*il2cpp_object_get_class_fn)(void* obj);
typedef void* (*il2cpp_class_get_field_from_name_fn)(void* klass, const char* name);
typedef void (*il2cpp_field_set_value_fn)(void* obj, void* field, void* value);
typedef const char* (*il2cpp_class_get_name_fn)(void* klass);

static il2cpp_resolve_icall_fn il2cpp_resolve_icall = nullptr;
static il2cpp_object_get_class_fn il2cpp_object_get_class = nullptr;
static il2cpp_class_get_field_from_name_fn il2cpp_class_get_field_from_name = nullptr;
static il2cpp_field_set_value_fn il2cpp_field_set_value = nullptr;
static il2cpp_class_get_name_fn il2cpp_class_get_name = nullptr;

typedef void* (*AssetBundle_LoadFromFile_t)(MyIl2CppString* path, uint32_t crc, uint64_t offset);
typedef void* (*AssetBundle_LoadAllAssets_t)(void* bundle, void* type);

static AssetBundle_LoadFromFile_t Unity_LoadFromFile = nullptr;
static AssetBundle_LoadAllAssets_t Unity_LoadAllAssets = nullptr;

static const std::unordered_map<std::string, std::string> translation_dict = {
    {"상점", "商店"},
    {"친구", "好友"},
    {"이벤트 팝업", "活动弹窗"},
    {"레벨 패斯", "等级通行证"},
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

// ==================== 唤醒与雷达扫描模块 ====================
static bool g_font_loaded = false;
void load_chinese_font_asset() {
    if (g_font_loaded || !il2cpp_resolve_icall || !il2cpp_string_new) return;

    Unity_LoadFromFile = (AssetBundle_LoadFromFile_t)il2cpp_resolve_icall("UnityEngine.AssetBundle::LoadFromFile_Internal(System.String,System.UInt32,System.UInt64)");
    Unity_LoadAllAssets = (AssetBundle_LoadAllAssets_t)il2cpp_resolve_icall("UnityEngine.AssetBundle::LoadAllAssets_Internal(System.Type)");

    if (Unity_LoadFromFile && Unity_LoadAllAssets) {
        const char* target_path = "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans";
        MyIl2CppString* bundle_path = il2cpp_string_new(target_path);
        
        LOGI("【雷达】正在尝试从路径加载 AB 包: %s", target_path);
        void* font_bundle = Unity_LoadFromFile(bundle_path, 0, 0);

        if (font_bundle) {
            LOGI("【雷达】物理加载成功！大箱子地址: %p。开始遍历内部资产...", font_bundle);
            void* assets_array = Unity_LoadAllAssets(font_bundle, nullptr);
            
            if (assets_array) {
                // 打印周边内存，暴力扫描究竟哪个位置才是真的 FontAsset
                for (int i = 0; i < 10; i++) {
                    void* test_ptr = ((void**)assets_array)[i];
                    if (test_ptr && il2cpp_object_get_class && il2cpp_class_get_name) {
                        void* klass = il2cpp_object_get_class(test_ptr);
                        const char* class_name = il2cpp_class_get_name(klass);
                        LOGI("【雷达扫描】数组下标 [%d] 处的资产类型为: %s, 指针: %p", i, class_name, test_ptr);
                        
                        // 如果名字里面包含 FontAsset，说明抓到正主了！
                        if (strstr(class_name, "FontAsset") != nullptr || strstr(class_name, "TMP_Font") != nullptr) {
                            china_font_asset_ptr = test_ptr;
                            LOGI("🎯【精准锁定】在下标 [%d] 成功截获中文字体指针！", i);
                        }
                    }
                }
            } else {
                LOGE("【雷达错误】LoadAllAssets 返回了空解压数组！包内可能无资产。");
            }
        } else {
            LOGE("【雷达错误】Unity 引擎拒绝加载此包，请检查文件是否在 MT 里成功复制，或者文件是否损坏！");
        }
    }
    g_font_loaded = true;
}

// ==================== TextMeshPro 文本挂钩拦截 ====================
static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    MyIl2CppString* final_string = il2cpp_string;

    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string origin_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
        auto it = translation_dict.find(origin_text);
        
        if (it != translation_dict.end()) {
            std::string translated_text = it->second;
            if (il2cpp_string_new != nullptr) {
                final_string = il2cpp_string_new(translated_text.c_str());
                
                // 如果抓到了中文字体指针，尝试注入
                if (china_font_asset_ptr != nullptr && __this != nullptr && il2cpp_object_get_class && il2cpp_class_get_field_from_name && il2cpp_field_set_value) {
                    void* text_klass = il2cpp_object_get_class(__this);
                    if (text_klass) {
                        void* font_field = il2cpp_class_get_field_from_name(text_klass, "m_fontAsset");
                        if (font_field) {
                            // 安全注入防护
                            il2cpp_field_set_value(__this, font_field, &china_font_asset_ptr);
                        }
                    }
                }
            }
        }
    }
    old_set_text(__this, final_string);
}

void hack_start(const char *game_data_dir) {
    LOGI("hack_start started...");
    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            il2cpp_string_new = (il2cpp_string_new_ptr)xdl_sym(handle, "il2cpp_string_new", nullptr);
            il2cpp_resolve_icall = (il2cpp_resolve_icall_fn)xdl_sym(handle, "il2cpp_resolve_icall", nullptr);
            il2cpp_object_get_class = (il2cpp_object_get_class_fn)xdl_sym(handle, "il2cpp_object_get_class", nullptr);
            il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_fn)xdl_sym(handle, "il2cpp_class_get_field_from_name", nullptr);
            il2cpp_field_set_value = (il2cpp_field_set_value_fn)xdl_sym(handle, "il2cpp_field_set_value", nullptr);
            il2cpp_class_get_name = (il2cpp_class_get_name_fn)xdl_sym(handle, "il2cpp_class_get_name", nullptr);

            if (il2cpp_resolve_icall != nullptr) {
                load_chinese_font_asset();
            }

            uintptr_t il2cpp_base = get_module_base("libil2cpp.so");
            if (il2cpp_base != 0) {
                void* set_text_addr = (void*)(il2cpp_base + 0xb5b099c);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】TextMeshPro::set_text 诊断挂钩完成！");
            }
            break;
        } else {
            sleep(1);
        }
    }
}

// ==================== 原封不动的底层兼容与 JNI 桥接 ====================
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
