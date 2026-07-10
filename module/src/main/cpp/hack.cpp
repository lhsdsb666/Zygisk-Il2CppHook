// Created by Perfare on 2020/7/4.
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
#include <fstream>
#include <sstream>
#include <unordered_map>

extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// ==================== 基础工具函数 ====================
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

void my_exit(int status) { LOGI("【Hook】Blocked exit(%d)!", status); while (true) { sleep(3600); } }
void my__exit(int status) { LOGI("【Hook】Blocked _exit(%d)!", status); while (true) { sleep(3600); } }

void hook_exit_functions() {
    void* libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc != nullptr) {
        void* exit_sym = dlsym(libc, "exit");
        if (exit_sym) DobbyHook(exit_sym, (void*)my_exit, (void**)&old_exit);
        void* _exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) DobbyHook(_exit_sym, (void*)my__exit, (void**)&old__exit);
    }
    LOGI("【Hook】Exit blocker active.");
}

// ==================== TextMeshPro 文本拦截器 ====================
struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0];
};

std::unordered_map<std::string, std::string> translation_map;
static MyIl2CppString* (*il2cpp_string_new_ptr)(const char* str) = nullptr;

std::string utf16_to_utf8(const char16_t* utf16, int len) {
    std::string utf8;
    for (int i = 0; i < len; ++i) {
        unsigned long cp = utf16[i];
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < len) {
            unsigned long trail = utf16[i + 1];
            if (trail >= 0xdc00 && trail <= 0xdfff) {
                cp = (cp - 0xd800) << 10 | (trail - 0xdc00); cp += 0x10000; i++;
            }
        }
        if (cp <= 0x7f) utf8 += (char)cp;
        else if (cp <= 0x7ff) { utf8 += (char)(0xc0 | (cp >> 6)); utf8 += (char)(0x80 | (cp & 0x3f)); }
        else if (cp <= 0xffff) { utf8 += (char)(0xe0 | (cp >> 12)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f)); }
        else { utf8 += (char)(0xf0 | (cp >> 18)); utf8 += (char)(0x80 | ((cp >> 12) & 0x3f)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f)); }
    }
    return utf8;
}

void load_translation_dict() {
    std::string path = "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/string_data.txt";
    std::ifstream file(path);
    if (!file.is_open()) {
        LOGI("【汉化提示】未能打开字典文件，请检查路径或权限！");
        return;
    }
    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            translation_map[line.substr(0, pos)] = line.substr(pos + 1);
            count++;
        }
    }
    file.close();
    LOGI("【汉化提示】字典加载成功！共读入 %d 条翻译词条。", count);
}

static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string original_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
        auto it = translation_map.find(original_text);
        if (it != translation_map.end()) {
            if (il2cpp_string_new_ptr != nullptr) {
                MyIl2CppString* new_string = il2cpp_string_new_ptr(it->second.c_str());
                if (new_string != nullptr) {
                    LOGI("【汉化匹配】成功替换: %s -> %s", original_text.c_str(), it->second.c_str());
                    return old_set_text(__this, new_string);
                } else {
                    LOGI("【汉化错误】il2cpp_string_new 内存分配失败：%s", it->second.c_str());
                }
            } else {
                LOGI("【汉化错误】无法替换！il2cpp_string_new 符号指针为空！");
            }
        } else {
            LOGI("【文本捕获】字数: %d | 内容: %s", il2cpp_string->length, original_text.c_str());
        }
    }
    old_set_text(__this, il2cpp_string);
}

// ==================== 新版 deod 解密捕获 ====================
// 目标函数签名已修正为: public static Byte[] deod(gnx a)
// 此时 deod 是静态函数，执行后直接返回包含明文/密文数据的 Byte[] 数组指针

static bool deod_dumped = false;
static void* (*old_deod)(void* gnx_a, void* method_info) = nullptr;

// kr.client 加密内容的固定头部签名
static const uint8_t KR_CLIENT_SIG[16] = {
    0x66,0x51,0xde,0x9f,0x0b,0xd4,0x25,0x06,
    0x7d,0xd6,0x01,0x16,0x20,0xcf,0xf4,0xd5
};

void* my_deod(void* gnx_a, void* method_info) {
    // 先调用原始函数，获取它返回的 Byte[] 数组指针
    void* arr = old_deod(gnx_a, method_info);

    if (arr != nullptr) {
        // 解析 Il2CppArray 结构获取长度与数据首地址
        uint64_t arr_len  = *(uint64_t*)((uint8_t*)arr + 0x18);
        uint8_t* arr_data = (uint8_t*)arr + 0x20;

        if (arr_len > 0 && arr_data != nullptr) {
            // 1. 提取前 16 字节打印到日志，方便在 Logcat 中肉眼观察数据特征
            char hex_str[64] = {0};
            for (int i = 0; i < (arr_len < 16 ? arr_len : 16); i++) {
                sprintf(hex_str + strlen(hex_str), "%02X ", arr_data[i]);
            }
            LOGI("【deod拦截】函数调用成功 | 返回数组长度=%lu | 前16字节Hex: %s", (unsigned long)arr_len, hex_str);

            // 2. 特征匹配判定
            bool is_encrypted_kr = (arr_len >= 16 && memcmp(arr_data, KR_CLIENT_SIG, 16) == 0);
            
            static const uint8_t UNITYFS_SIG[7] = {0x55, 0x6E, 0x69, 0x74, 0x79, 0x46, 0x53}; // "UnityFS"
            bool is_unity_fs = (arr_len >= 7 && memcmp(arr_data, UNITYFS_SIG, 7) == 0);

            // 3. 触发转存：如果是 kr 密文、或者是解密后的 UnityFS 资产、或者文件大于 500KB，统统捞出来
            if (is_unity_fs || is_encrypted_kr || arr_len > 500000) {
                char out_path[128];
                if (is_unity_fs) {
                    snprintf(out_path, sizeof(out_path), "/sdcard/Download/decrypted_unityfs_%lu.bin", (unsigned long)arr_len);
                } else if (is_encrypted_kr) {
                    snprintf(out_path, sizeof(out_path), "/sdcard/Download/encrypted_kr_%lu.bin", (unsigned long)arr_len);
                } else {
                    snprintf(out_path, sizeof(out_path), "/sdcard/Download/dumped_asset_%lu.bin", (unsigned long)arr_len);
                }

                FILE* f = fopen(out_path, "wb");
                if (f != nullptr) {
                    size_t written = fwrite(arr_data, 1, (size_t)arr_len, f);
                    fclose(f);
                    deod_dumped = true;
                    LOGI("【解密Dump】成功捕获目标！已保存 %zu 字节到 %s", written, out_path);
                } else {
                    LOGI("【解密Dump】写文件失败！请检查外置存储写入权限。路径：%s", out_path);
                }
            }
        }
    }

    return arr;
}

// ==================== 主入口 ====================
void hack_start(const char *game_data_dir) {
    LOGI("hack_start inside, waiting for libil2cpp.so...");
    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            hook_exit_functions();
            uintptr_t il2cpp_base = get_module_base("libil2cpp.so");
            if (il2cpp_base != 0) {
                il2cpp_string_new_ptr = (MyIl2CppString* (*)(const char*))xdl_sym(handle, "il2cpp_string_new", nullptr);
                if (il2cpp_string_new_ptr != nullptr) {
                    LOGI("【成功】成功通过 xdl 绑定 il2cpp_string_new，地址：%p", il2cpp_string_new_ptr);
                } else {
                    LOGI("【严重错误】未能通过 xdl 找到 il2cpp_string_new 符号！");
                }

                load_translation_dict();

                // Hook TextMeshPro set_text（原有汉化功能）
                // 已经替换为最新 RVA 地址: 0xb670210
                void* set_text_addr = (void*)(il2cpp_base + 0xb670210);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】TextMeshPro::set_text 挂钩完成");

                // Hook qpu.deod（当前版本 dump.cs 确证的真实解密出口）
                // 已经替换为最新 RVA 地址: 0x5edf60c
                void* deod_addr = (void*)(il2cpp_base + 0x5edf60c);
                DobbyHook(deod_addr, (void*)my_deod, (void**)&old_deod);
                LOGI("【成功】qpu::deod 解密捕获 Hook 已安装，真实偏移 0x5edf60c，等待资产加载...");
            }
            break;
        }
        sleep(1);
    }
}

// ==================== 模拟器环境兼容代码 ====================
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
                        std::string lib_dir(path); env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    }
                }
            }
        }
    }
    return {};
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
    if (JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms) == JNI_OK && num_vms > 0) { vms = vms_buf[0]; } else { return false; }
    auto lib_dir = GetLibDir(vms);
    if (lib_dir.empty() || lib_dir.find("/lib/x86") != std::string::npos) { munmap(data, length); return false; }
    char val[PROP_VALUE_MAX]; __system_property_get("ro.dalvik.vm.native.bridge", val);
    auto nb = dlopen("libhoudini.so", RTLD_NOW); if (!nb) nb = dlopen(val, RTLD_NOW);
    if (nb) {
        auto callbacks = (NativeBridgeCallbacks *) dlsym(nb, "NativeBridgeItf");
        if (callbacks) {
            int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC); ftruncate(fd, (off_t) length);
            void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0); memcpy(mem, data, length);
            munmap(mem, length); munmap(data, length); char path[PATH_MAX]; snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
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
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length))
#endif
    hack_start(game_data_dir);
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    std::thread hack_thread(hack_start, (const char *) reserved);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
