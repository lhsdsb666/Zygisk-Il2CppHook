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
#include <unordered_map> 

// ===== 直接前置声明 Dobby 函数 =====
extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// ==================== Unity 底层字符串结构与 API 定义 ====================
struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0]; 
};

// 定义 il2cpp_string_new 函数指针，用来动态创建 C# 字符串
typedef MyIl2CppString* (*il2cpp_string_new_ptr)(const char* text);
static il2cpp_string_new_ptr il2cpp_string_new = nullptr;

// 用于存储从国服动态加载的字体资产指针（保留后续代码层直接注入的能力）
static void* china_font_asset_ptr = nullptr;

// ===== 新增：IL2CPP 运行时反射与 iCall 函数指针定义 =====
typedef void* (*il2cpp_resolve_icall_fn)(const char* name);
typedef void* (*il2cpp_object_get_class_fn)(void* obj);
typedef void* (*il2cpp_class_get_field_from_name_fn)(void* klass, const char* name);
typedef void (*il2cpp_field_set_value_fn)(void* obj, void* field, void* value);

static il2cpp_resolve_icall_fn il2cpp_resolve_icall = nullptr;
static il2cpp_object_get_class_fn il2cpp_object_get_class = nullptr;
static il2cpp_class_get_field_from_name_fn il2cpp_class_get_field_from_name = nullptr;
static il2cpp_field_set_value_fn il2cpp_field_set_value = nullptr;

typedef void* (*AssetBundle_LoadFromFile_t)(MyIl2CppString* path, uint32_t crc, uint64_t offset);
typedef void* (*AssetBundle_LoadAllAssets_t)(void* bundle, void* type);

static AssetBundle_LoadFromFile_t Unity_LoadFromFile = nullptr;
static AssetBundle_LoadAllAssets_t Unity_LoadAllAssets = nullptr;
// =======================================================

// ==================== 简易汉化字典 ====================
static const std::unordered_map<std::string, std::string> translation_dict = {
    {"상점", "商店"},
    {"친구", "好友"},
    {"이벤트 팝업", "活动弹窗"},
    {"레벨 패스", "等级通行证"},
    {"BETA", "测试版"}
};

// UTF-16 转 UTF-8 转换函数
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

// 获取模块基地址
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

// ==================== Hook 退出函数（防反作弊自杀） ====================
static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;
static void (*old_abort)() = nullptr;

void my_exit(int status) {
    LOGI("【Hook】Blocked exit(%d) ! 阻止游戏自杀", status);
    while (true) { sleep(3600); }
}
void my__exit(int status) {
    LOGI("【Hook】Blocked _exit(%d) ! 阻止游戏自杀", status);
    while (true) { sleep(3600); }
}
void my_abort() {
    LOGI("【Hook】Blocked abort() ! 阻止游戏自杀");
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
    void* abort_sym = dlsym(RTLD_DEFAULT, "abort");
    if (abort_sym) DobbyHook(abort_sym, (void*)my_abort, (void**)&old_abort);
}

// ===== 新增：独立安全的外部字库唤醒模块 =====
static bool g_font_loaded = false;
void load_chinese_font_asset() {
    if (g_font_loaded || !il2cpp_resolve_icall || !il2cpp_string_new) return;

    // 吟唱字符串，通过 iCall 白名单机制无缝穿透获取 Unity 官方底层的加载函数
    Unity_LoadFromFile = (AssetBundle_LoadFromFile_t)il2cpp_resolve_icall("UnityEngine.AssetBundle::LoadFromFile_Internal(System.String,System.UInt32,System.UInt64)");
    Unity_LoadAllAssets = (AssetBundle_LoadAllAssets_t)il2cpp_resolve_icall("UnityEngine.AssetBundle::LoadAllAssets_Internal(System.Type)");

    if (Unity_LoadFromFile && Unity_LoadAllAssets) {
        // 【已修正】完美匹配长官 MT 管理器截图中的韩服外置沙盒绝对路径
        MyIl2CppString* bundle_path = il2cpp_string_new("/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans");
        void* font_bundle = Unity_LoadFromFile(bundle_path, 0, 0);

        if (font_bundle) {
            LOGI("【成功】国服 zh-hans 资产包物理唤醒成功！开始盲读内部资产...");
            // 传入 nullptr，盲捞 AB 包内的全量资源
            void* assets_array = Unity_LoadAllAssets(font_bundle, nullptr);
            if (assets_array) {
                // 【已修正】64位 Unity 环境下，C# 数组的第一个有效元素资产（Element 0）存放在指针数组的第 4 项（下标为 4）
                china_font_asset_ptr = ((void**)assets_array)[4];
                LOGI("【核心突破】成功捕获中文字体内存指针，地址: %p", china_font_asset_ptr);
            }
        } else {
            // 【已修正】同步更新警报日志路径，方便看 Log 诊断
            LOGE("【警报】未在指定路径 /storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans 找到字库文件！");
        }
    } else {
        LOGE("【致命错误】通过 iCall 绑定 Unity 底层文件加载 API 失败！");
    }
    g_font_loaded = true;
}
// =====================================================

// ==================== TextMeshPro 文本拦截与替换器 ====================
static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    MyIl2CppString* final_string = il2cpp_string;

    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        // 1. 解析当前文本
        std::string origin_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
        
        // 2. 查字典看看有没有汉化文本
        auto it = translation_dict.find(origin_text);
        if (it != translation_dict.end()) {
            std::string translated_text = it->second;
            
            // 3. 如果找到了翻译，并且 il2cpp_string_new 成功加载，就动态生成新的 C# 字符串
            if (il2cpp_string_new != nullptr) {
                final_string = il2cpp_string_new(translated_text.c_str());
                LOGI("【成功汉化】%s -> %s", origin_text.c_str(), translated_text.c_str());
                
                // ===== 新增：动态字段流——后台偷偷递上中文箱子 =====
                if (china_font_asset_ptr != nullptr && __this != nullptr && il2cpp_object_get_class && il2cpp_class_get_field_from_name && il2cpp_field_set_value) {
                    void* text_klass = il2cpp_object_get_class(__this);
                    if (text_klass) {
                        // 动态反射抓取当前 TMP 控件的主字体属性字段 m_fontAsset
                        void* font_field = il2cpp_class_get_field_from_name(text_klass, "m_fontAsset");
                        if (font_field) {
                            // 【已修正】强行把主字体掉包成国服中文字体指针（il2cpp_field_set_value 对引用类型必须传指针的地址 `&`）
                            il2cpp_field_set_value(__this, font_field, &china_font_asset_ptr);
                            LOGI("【内存掉包】成功将 TMP 控件 %p 的 m_fontAsset 变更为中文库！", __this);
                        }
                    }
                }
                // ===================================================
            }
        } else {
            // 没在字典里的词，打印出来方便收集
            LOGI("【未翻译文本】内容: %s", origin_text.c_str());
        }
    }
    
    // 放行给原函数
    old_set_text(__this, final_string);
}

void hack_start(const char *game_data_dir) {
    bool load = false;
    LOGI("hack_start started, waiting for libil2cpp.so...");

    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            load = true;
            LOGI("Found libil2cpp.so! Starting hooks...");

            // 1. 安装退出 Hook
            hook_exit_functions();

            // 2. 动态定位并获取 Unity 官方的字符串创建函数
            il2cpp_string_new = (il2cpp_string_new_ptr)xdl_sym(handle, "il2cpp_string_new", nullptr);
            if (il2cpp_string_new != nullptr) {
                LOGI("【成功】获取到 il2cpp_string_new 导出函数！");
            } else {
                LOGE("【失败】未找到 il2cpp_string_new 导出函数！");
            }

            // ===== 新增：动态绑定 IL2CPP 核心基建 API =====
            il2cpp_resolve_icall = (il2cpp_resolve_icall_fn)xdl_sym(handle, "il2cpp_resolve_icall", nullptr);
            il2cpp_object_get_class = (il2cpp_object_get_class_fn)xdl_sym(handle, "il2cpp_object_get_class", nullptr);
            il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_fn)xdl_sym(handle, "il2cpp_class_get_field_from_name", nullptr);
            il2cpp_field_set_value = (il2cpp_field_set_value_fn)xdl_sym(handle, "il2cpp_field_set_value", nullptr);

            // 基建 API 成功就位后，立刻在后台安全加载国服字库
            if (il2cpp_resolve_icall != nullptr) {
                load_chinese_font_asset();
            }
            // ============================================

            // 3. 获取基地址并挂钩文本函数
            uintptr_t il2cpp_base = get_module_base("libil2cpp.so");
            if (il2cpp_base != 0) {
                LOGI("【成功】安全获取到 il2cpp 基地址: 0x%llx", (unsigned long long)il2cpp_base);
                
                // 对应你的 RVA 基地址 0xb5b099c
                void* set_text_addr = (void*)(il2cpp_base + 0xb5b099c);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】TextMeshPro::set_text 挂钩完成！");
            } else {
                LOGE("【失败】未能获取到 il2cpp 基地址");
            }
            break;
        } else {
            sleep(1);
        }
    }
}

// ==================== 后续原封不动的底层适配代码 ====================
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
