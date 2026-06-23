//
// Created by Perfare on 2020/7/4.
// 完美解决 Split APK 虚拟路径问题的终极版 hack.cpp (真·Font Fallback 级联进化版)
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

typedef void* (*il2cpp_resolve_icall_fn)(const char* name);
typedef void* (*il2cpp_object_get_class_fn)(void* obj);
typedef void* (*il2cpp_class_get_field_from_name_fn)(void* klass, const char* name);
typedef void (*il2cpp_field_set_value_fn)(void* obj, void* field, void* value);
typedef void (*il2cpp_field_get_value_fn)(void* obj, void* field, void* value); // 【新增】读取字段值接口
typedef void* (*il2cpp_class_get_method_from_name_fn)(void* klass, const char* name, int argsCount); // 【新增】查找方法接口
typedef void* (*il2cpp_runtime_invoke_fn)(void* method, void* obj, void** args, void** exc); // 【新增】调用方法接口
typedef const char* (*il2cpp_class_get_name_fn)(void* klass);

static il2cpp_resolve_icall_fn il2cpp_resolve_icall = nullptr;
static il2cpp_object_get_class_fn il2cpp_object_get_class = nullptr;
static il2cpp_class_get_field_from_name_fn il2cpp_class_get_field_from_name = nullptr;
static il2cpp_field_set_value_fn il2cpp_field_set_value = nullptr;
static il2cpp_field_get_value_fn il2cpp_field_get_value = nullptr; // 【新增】
static il2cpp_class_get_method_from_name_fn il2cpp_class_get_method_from_name = nullptr; // 【新增】
static il2cpp_runtime_invoke_fn il2cpp_runtime_invoke = nullptr; // 【新增】
static il2cpp_class_get_name_fn il2cpp_class_get_name = nullptr;

typedef void* (*AssetBundle_LoadFromFile_t)(MyIl2CppString* path, uint32_t crc, uint64_t offset);
typedef void* (*AssetBundle_LoadAllAssets_t)(void* bundle, void* type);

static AssetBundle_LoadFromFile_t Unity_LoadFromFile = nullptr;
static AssetBundle_LoadAllAssets_t Unity_LoadAllAssets = nullptr;

// ==================== 简易汉化字典 ====================
static const std::unordered_map<std::string, std::string> translation_dict = {
    {"상점", "商店"},
    {"친구", "好友"},
    {"이벤트 팝업", "活动弹窗"},
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

// ===== 核心新增：直接从内核内存盘中榨取带有"!"的完整分包物理路径 =====
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

// ==================== 外部字库唤醒模块 ====================
static bool g_font_loaded = false;
void load_chinese_font_asset() {
    if (g_font_loaded || !il2cpp_resolve_icall || !il2cpp_string_new) return;

    Unity_LoadFromFile = (AssetBundle_LoadFromFile_t)il2cpp_resolve_icall("UnityEngine.AssetBundle::LoadFromFile_Internal(System.String,System.UInt32,System.UInt64)");
    Unity_LoadAllAssets = (AssetBundle_LoadAllAssets_t)il2cpp_resolve_icall("UnityEngine.AssetBundle::LoadAllAssets_Internal(System.Type)");

    if (Unity_LoadFromFile && Unity_LoadAllAssets) {
        MyIl2CppString* bundle_path = il2cpp_string_new("/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans");
        void* font_bundle = Unity_LoadFromFile(bundle_path, 0, 0);

        if (font_bundle) {
            LOGI("【雷达】物理加载成功！大箱子地址: %p。开始遍历内部资产...", font_bundle);
            void* assets_array = Unity_LoadAllAssets(font_bundle, nullptr);
            if (assets_array) {
                // 【核心修复】安全获取 64位 IL2CPP 数组的真实长度（第 0x18 字节处）
                int32_t array_length = *(int32_t*)((uintptr_t)assets_array + 0x18);
                // 【核心修复】定位数据元素真正开始的指针偏移（第 0x20 字节处），彻底告别 [3] 地雷
                void** items = (void**)((uintptr_t)assets_array + 0x20);

                LOGI("【雷达扫描】侦测到字库包内共有 %d 个资产，开始进行类型校对对齐...", array_length);
                for (int i = 0; i < array_length; i++) {
                    void* test_ptr = items[i];
                    if (test_ptr && il2cpp_object_get_class && il2cpp_class_get_name) {
                        void* klass = il2cpp_object_get_class(test_ptr);
                        const char* class_name = il2cpp_class_get_name(klass);
                        LOGI("【雷达扫描】资产下标 [%d] 处的类名: %s", i, class_name);
                        
                        if (strstr(class_name, "FontAsset") != nullptr || strstr(class_name, "TMP_Font") != nullptr) {
                            china_font_asset_ptr = test_ptr;
                            LOGI("🎯【精准锁定】在安全下标 [%d] 拦截并捕获中文字体资产指针: %p", i, china_font_asset_ptr);
                            break; 
                        }
                    }
                }
            }
        } else {
            LOGE("【雷达错误】未在外部沙盒找到字库包 zh-hans 或文件损坏！");
        }
    }
    g_font_loaded = true;
}

// ==================== TextMeshPro 文本拦截与替换器 ====================
static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;
static bool s_fallback_injected = false; // 全局锁，确保后备字库链只挂载一次

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    MyIl2CppString* final_string = il2cpp_string;

    // 环节一：文本字典翻译
    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string origin_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
        auto it = translation_dict.find(origin_text);
        if (it != translation_dict.end()) {
            std::string translated_text = it->second;
            if (il2cpp_string_new != nullptr) {
                final_string = il2cpp_string_new(translated_text.c_str());
                LOGI("【成功汉化】%s -> %s", origin_text.c_str(), translated_text.c_str());
            }
        }
    }

    // 环节二：【重大重构】真·后备字库挂载逻辑（Font Fallback 级联技术）
    if (!s_fallback_injected && china_font_asset_ptr != nullptr && __this != nullptr && 
        il2cpp_object_get_class && il2cpp_class_get_field_from_name && 
        il2cpp_field_get_value && il2cpp_class_get_method_from_name && il2cpp_runtime_invoke) {
        
        void* text_klass = il2cpp_object_get_class(__this);
        if (text_klass) {
            // 1. 抓取文本控件身上的主字体字段实例
            void* font_field = il2cpp_class_get_field_from_name(text_klass, "m_fontAsset");
            if (font_field) {
                void* korean_main_font = nullptr;
                il2cpp_field_get_value(__this, font_field, &korean_main_font);
                
                if (korean_main_font) {
                    void* font_klass = il2cpp_object_get_class(korean_main_font);
                    if (font_klass) {
                        // 2. 注入你在 dump.cs 里精准挖到的 Unity 6 关键后备列表字段："m_FallbackFontAssetTable"
                        void* fallback_field = il2cpp_class_get_field_from_name(font_klass, "m_FallbackFontAssetTable");
                        if (fallback_field) {
                            void* fallback_list_obj = nullptr;
                            il2cpp_field_get_value(korean_main_font, fallback_field, &fallback_list_obj);
                            
                            if (fallback_list_obj) {
                                void* list_klass = il2cpp_object_get_class(fallback_list_obj);
                                if (list_klass) {
                                    // 3. 反射获取系统 List.Add(T item) 的原生底层方法
                                    void* add_method = il2cpp_class_get_method_from_name(list_klass, "Add", 1);
                                    if (add_method) {
                                        // 4. 将提取出的国服 4K 中文字体指针追加到韩服原版列表末尾
                                        void* args[1] = { china_font_asset_ptr };
                                        il2cpp_runtime_invoke(add_method, fallback_list_obj, args, nullptr);
                                        
                                        LOGI("🎯【Fallback 成功】已成功将国服 4K 中文字库挂载为韩服主字体的后备链 (m_FallbackFontAssetTable)！");
                                        s_fallback_injected = true; // 功成身退，永久锁定不再重复注入
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 照常把文本送回原始渲染。遇到没有汉字的韩文用原版图，遇到汉字自动去中文 4K 图里捞！
    old_set_text(__this, final_string);
}

// ==================== 突破改造后的核心启动器 ====================
void hack_start(const char *game_data_dir) {
    LOGI("hack_start started, entering deployment loop...");
    hook_exit_functions(); // 提前安装防自杀 Hook

    uintptr_t il2cpp_base = 0;
    for (int i = 0; i < 300; i++) {
        // 核心修复：直接从内存抓取最真实的物理分包路径
        std::string real_path = get_module_path_and_base("libil2cpp.so", il2cpp_base);
        
        if (!real_path.empty() && il2cpp_base != 0) {
            LOGI("【核心发现】成功从内存抓取到 il2cpp 真实绝对路径: %s", real_path.c_str());
            LOGI("【核心发现】安全捕获基地址: 0x%llx", (unsigned long long)il2cpp_base);
            
            // 三路闭环句柄加载机制
            void *handle = xdl_open(real_path.c_str(), 0); // 1. 尝试绝对路径
            if (!handle) {
                handle = xdl_open("libil2cpp.so", 0);      // 2. 尝试标准盲搜
            }
            if (!handle) {
                handle = dlopen(real_path.c_str(), RTLD_LAZY); // 3. 尝试原生 dlopen
            }

            if (handle) {
                LOGI("【成功】libil2cpp.so 核心句柄接驳成功！开始绑定运行时接口...");
                
                // 智能符号查找器
                auto find_sym = [](void* h, const char* name) -> void* {
                    void* sym = xdl_sym(h, name, nullptr);
                    if (!sym) sym = dlsym(h, name);
                    return sym;
                };

                il2cpp_string_new = (il2cpp_string_new_ptr)find_sym(handle, "il2cpp_string_new");
                il2cpp_resolve_icall = (il2cpp_resolve_icall_fn)find_sym(handle, "il2cpp_resolve_icall");
                il2cpp_object_get_class = (il2cpp_object_get_class_fn)find_sym(handle, "il2cpp_object_get_class");
                il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_fn)find_sym(handle, "il2cpp_class_get_field_from_name");
                il2cpp_field_set_value = (il2cpp_field_set_value_fn)find_sym(handle, "il2cpp_field_set_value");
                il2cpp_field_get_value = (il2cpp_field_get_value_fn)find_sym(handle, "il2cpp_field_get_value"); // 【新增符号绑定】
                il2cpp_class_get_method_from_name = (il2cpp_class_get_method_from_name_fn)find_sym(handle, "il2cpp_class_get_method_from_name"); // 【新增符号绑定】
                il2cpp_runtime_invoke = (il2cpp_runtime_invoke_fn)find_sym(handle, "il2cpp_runtime_invoke"); // 【新增符号绑定】
                il2cpp_class_get_name = (il2cpp_class_get_name_fn)find_sym(handle, "il2cpp_class_get_name");

                // 基建就位，立刻唤醒国服中文字库
                if (il2cpp_resolve_icall != nullptr) {
                    load_chinese_font_asset();
                }

                // 进行 TextMeshPro 函数 Hook 挂载
                void* set_text_addr = (void*)(il2cpp_base + 0xb5b099c);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】TextMeshPro::set_text 核心 Hook 部署完毕！");
                break;
            } else {
                LOGE("【警报】已抓到路径，但所有句柄加载器均告失败，第 %d 次重试...", i);
            }
        } else {
            if (i % 5 == 0) {
                LOGI("【等待】libil2cpp.so 尚未被 Unity 加载进内存，持续监控中... (%d/300)", i);
            }
        }
        sleep(1);
    }
}

// ==================== 原封不动的底层适配与桥接代码 ====================
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
