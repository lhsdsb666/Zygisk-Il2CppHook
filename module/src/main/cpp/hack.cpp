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
#include <unordered_set>
#include <cstdlib>

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
std::unordered_set<std::string> captured_kr_texts;
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

bool contains_korean(const char16_t* chars, int len) {
    for (int i = 0; i < len; i++) {
        char16_t c = chars[i];
        if ((c >= 0xAC00 && c <= 0xD7A3) || (c >= 0x1100 && c <= 0x11FF) || (c >= 0x3130 && c <= 0x318F))
            return true;
    }
    return false;
}

void load_translation_dict() {
    std::string path = "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/string_data.txt";
    std::ifstream file(path);
    if (!file.is_open()) { LOGI("【汉化提示】未能打开字典文件！"); return; }
    std::string line; int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        size_t pos = line.find('=');
        if (pos != std::string::npos) { translation_map[line.substr(0, pos)] = line.substr(pos + 1); count++; }
    }
    file.close();
    LOGI("【汉化提示】字典加载成功！共读入 %d 条翻译词条。", count);
}

static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string original_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);
        if (contains_korean(il2cpp_string->chars, il2cpp_string->length)) {
            if (captured_kr_texts.find(original_text) == captured_kr_texts.end()) {
                captured_kr_texts.insert(original_text);
                FILE* f = fopen("/sdcard/Download/captured_korean.txt", "a");
                if (f) {
                    std::string safe = original_text;
                    size_t p = 0;
                    while ((p = safe.find('\n', p)) != std::string::npos) { safe.replace(p, 1, "\\n"); p += 2; }
                    fprintf(f, "%s\n", safe.c_str()); fclose(f);
                }
            }
        }
        auto it = translation_map.find(original_text);
        if (it != translation_map.end()) {
            if (il2cpp_string_new_ptr != nullptr) {
                MyIl2CppString* new_string = il2cpp_string_new_ptr(it->second.c_str());
                if (new_string != nullptr) {
                    LOGI("【汉化匹配】%s -> %s", original_text.c_str(), it->second.c_str());
                    return old_set_text(__this, new_string);
                }
            }
        } else {
            LOGI("【文本捕获】%s", original_text.c_str());
        }
    }
    old_set_text(__this, il2cpp_string);
}

// ==================== 核心：拦截 MessagePack 明文 ====================
//
// 目标函数：public static gop deop(Byte[] a)   RVA: 0x5edfa94
//
// 逻辑：
//   kr.client 解密完成后，游戏调用 deop() 把解密后的字节数组
//   解析成 gop（游戏数据对象）。参数 a 就是完整的明文 MessagePack 数据。
//   我们在它被解析之前把 a 的内容存到文件——这就是明文。
//
// 输出：/sdcard/Download/kr_plaintext.bin
//   拿到这个文件之后：
//   1. 用 Python msgpack 库解析，得到所有韩文字符串
//   2. 翻译成中文
//   3. 重新 msgpack 编码 → 重新加密 → 新的 kr.client
//
// 副目标：deob() 返回 Byte[]，可能是密钥或初始化数据
//   RVA: 0x5edf930，保存到 /sdcard/Download/deob_result.bin

// --- deop hook ---
static bool deop_dumped = false;
static void* (*old_deop)(void* arr_a) = nullptr;

void* my_deop(void* arr_a) {
    // 先保存数据，再交给原函数解析（保证游戏正常运行）
    if (!deop_dumped && arr_a != nullptr) {
        // Il2CppArray 结构：+0x18=长度, +0x20=数据
        uint64_t len  = *(uint64_t*)((uint8_t*)arr_a + 0x18);
        uint8_t* data = (uint8_t*)arr_a + 0x20;

        LOGI("【deop拦截】调用！数组长度=%lu 头4字节=%02X%02X%02X%02X",
             (unsigned long)len,
             len>0?data[0]:0, len>1?data[1]:0,
             len>2?data[2]:0, len>3?data[3]:0);

        // MessagePack 以 0x80-0x8F（fixmap）或 0x82/0xDE/0xDF 开头
        // 只保存看起来合理的数据（>1KB，避免小型无关调用）
        if (len > 1024 && len < 50 * 1024 * 1024) {
            deop_dumped = true;
            const char* out = "/sdcard/Download/kr_plaintext.bin";
            FILE* f = fopen(out, "wb");
            if (f) {
                fwrite(data, 1, (size_t)len, f);
                fclose(f);
                LOGI("【deop拦截】★★★ 成功保存 %lu 字节明文 -> %s", (unsigned long)len, out);
            } else {
                LOGI("【deop拦截】写文件失败！");
            }
        }
    }
    return old_deop(arr_a);
}

// --- deob hook（无参数，返回 Byte[]，可能是密钥）---
static bool deob_dumped = false;
static void* (*old_deob)() = nullptr;

void* my_deob() {
    void* result = old_deob();
    if (!deob_dumped && result != nullptr) {
        deob_dumped = true;
        uint64_t len  = *(uint64_t*)((uint8_t*)result + 0x18);
        uint8_t* data = (uint8_t*)result + 0x20;
        LOGI("【deob拦截】返回 %lu 字节，头16字节: %s",
             (unsigned long)len,
             [&]() -> std::string {
                 char buf[64] = {};
                 for (uint64_t i = 0; i < len && i < 16; i++)
                     snprintf(buf + strlen(buf), 4, "%02X ", data[i]);
                 return std::string(buf);
             }().c_str());
        if (len > 0 && len < 10 * 1024 * 1024) {
            const char* out = "/sdcard/Download/deob_result.bin";
            FILE* f = fopen(out, "wb");
            if (f) { fwrite(data, 1, (size_t)len, f); fclose(f); }
            LOGI("【deob拦截】已保存 -> %s", out);
        }
    }
    return result;
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
                if (il2cpp_string_new_ptr != nullptr)
                    LOGI("【成功】il2cpp_string_new 绑定 %p", il2cpp_string_new_ptr);
                else
                    LOGI("【错误】未能绑定 il2cpp_string_new");

                load_translation_dict();

                // Hook 1：文本渲染（汉化功能）
                void* set_text_addr = (void*)(il2cpp_base + 0xb670210);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】set_text Hook 完成");

                // Hook 2：deop(Byte[] a) — 拦截解密后的 MessagePack 明文
                // public static gop deop(Byte[] a)  RVA: 0x5edfa94
                void* deop_addr = (void*)(il2cpp_base + 0x5edfa94);
                DobbyHook(deop_addr, (void*)my_deop, (void**)&old_deop);
                LOGI("【成功】deop Hook 安装（RVA: 0x5edfa94），等待明文...");

                // Hook 3：deob() — 无参返回 Byte[]，可能是密钥
                // public static Byte[] deob()  RVA: 0x5edf930
                void* deob_addr = (void*)(il2cpp_base + 0x5edf930);
                DobbyHook(deob_addr, (void*)my_deob, (void**)&old_deob);
                LOGI("【成功】deob Hook 安装（RVA: 0x5edf930）");
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
