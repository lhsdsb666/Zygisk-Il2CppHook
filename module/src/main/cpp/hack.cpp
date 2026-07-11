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

        if (contains_korean(il2cpp_string->chars, il2cpp_string->length)) {
            if (captured_kr_texts.find(original_text) == captured_kr_texts.end()) {
                captured_kr_texts.insert(original_text);
                FILE* f = fopen("/sdcard/Download/captured_korean.txt", "a");
                if (f != nullptr) {
                    std::string safe = original_text;
                    size_t p = 0;
                    while ((p = safe.find('\n', p)) != std::string::npos) {
                        safe.replace(p, 1, "\\n"); p += 2;
                    }
                    fprintf(f, "%s\n", safe.c_str());
                    fclose(f);
                }
            }
        }

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

// ==================== gsm 构造函数 Hook（捕获加密密钥）====================
//
// 目标：gsm.ctor(Byte[] a, Byte[] b, Int32 c)  RVA: 0x5f2de0c
//
// 原理：
//   gsm 是负责 kr.client 加解密的类。
//   它的构造函数直接接收两个 Byte[] 参数 a 和 b，
//   这两个字节数组就是加密用的密钥和 IV（初始向量）。
//   我们只需要在构造函数被调用时，把 a 和 b 的内容
//   原样保存到文件，就得到了密钥。
//
// 输出文件：
//   /sdcard/Download/gsm_key_a.bin  ← 密钥 A（参数 a）
//   /sdcard/Download/gsm_key_b.bin  ← 密钥 B（参数 b）
//   /sdcard/Download/gsm_keys.txt   ← 两个密钥的 hex 文本，方便查看

static bool gsm_key_dumped = false;
static void (*old_gsm_ctor)(void* thisptr, void* arr_a, void* arr_b, int32_t c) = nullptr;

// 把 Il2CppArray 内容写到文件，同时返回 hex 字符串用于日志
std::string dump_il2cpp_array(const char* label, void* arr, const char* bin_path) {
    std::string hex_result = "(null)";

    if (arr == nullptr) {
        LOGI("【密钥捕获】%s = null，跳过", label);
        return hex_result;
    }

    // Il2CppArray 内存布局（64位）：
    //   +0x00  klass*        (8字节)
    //   +0x08  monitor*      (8字节)
    //   +0x10  bounds*       (8字节，一维数组为 null)
    //   +0x18  max_length    (uint64，数组元素个数)
    //   +0x20  data[]        (实际字节数据从这里开始)
    uint64_t len  = *(uint64_t*)((uint8_t*)arr + 0x18);
    uint8_t* data = (uint8_t*)arr + 0x20;

    if (len == 0 || len > 4096) {
        // 密钥一般不会超过 4KB，超出则说明地址有误
        LOGI("【密钥捕获】%s 长度异常: %lu，跳过", label, (unsigned long)len);
        return hex_result;
    }

    // 写二进制文件
    FILE* fb = fopen(bin_path, "wb");
    if (fb != nullptr) {
        fwrite(data, 1, (size_t)len, fb);
        fclose(fb);
        LOGI("【密钥捕获】%s 已写入 %s（%lu 字节）", label, bin_path, (unsigned long)len);
    } else {
        LOGI("【密钥捕获】%s 写文件失败: %s", label, bin_path);
    }

    // 生成 hex 字符串（用于日志和文本文件）
    hex_result.clear();
    char buf[4];
    for (uint64_t i = 0; i < len; i++) {
        snprintf(buf, sizeof(buf), "%02X", data[i]);
        hex_result += buf;
        if (i < len - 1) hex_result += " ";
    }

    return hex_result;
}

void my_gsm_ctor(void* thisptr, void* arr_a, void* arr_b, int32_t c) {
    // 先调用原始构造函数，保证游戏逻辑不受影响
    old_gsm_ctor(thisptr, arr_a, arr_b, c);

    // 只捕获一次（构造函数可能被多次调用，只要第一次即可）
    if (!gsm_key_dumped) {
        gsm_key_dumped = true;
        LOGI("【密钥捕获】gsm 构造函数触发！thisptr=%p  arr_a=%p  arr_b=%p  c=%d",
             thisptr, arr_a, arr_b, c);

        std::string hex_a = dump_il2cpp_array("密钥A", arr_a, "/sdcard/Download/gsm_key_a.bin");
        std::string hex_b = dump_il2cpp_array("密钥B", arr_b, "/sdcard/Download/gsm_key_b.bin");

        // 额外写一个可读的文本文件，方便直接查看
        FILE* ft = fopen("/sdcard/Download/gsm_keys.txt", "w");
        if (ft != nullptr) {
            fprintf(ft, "key_a_hex=%s\n", hex_a.c_str());
            fprintf(ft, "key_b_hex=%s\n", hex_b.c_str());
            fprintf(ft, "param_c=%d\n", c);
            fclose(ft);
        }

        LOGI("【密钥捕获】完成！");
        LOGI("【密钥捕获】key_a = %s", hex_a.c_str());
        LOGI("【密钥捕获】key_b = %s", hex_b.c_str());
        LOGI("【密钥捕获】param_c = %d", c);
        LOGI("【密钥捕获】三个文件已保存到 /sdcard/Download/");
    }
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

                // Hook 1：文本渲染拦截（原有汉化功能）
                void* set_text_addr = (void*)(il2cpp_base + 0xb670210);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】TextMeshPro::set_text 挂钩完成");

                // Hook 2：gsm 构造函数，捕获 kr.client 加密密钥
                // class gsm : glm，.ctor(Byte[] a, Byte[] b, Int32 c)
                // RVA: 0x5f2de0c
                void* gsm_ctor_addr = (void*)(il2cpp_base + 0x5f2de0c);
                DobbyHook(gsm_ctor_addr, (void*)my_gsm_ctor, (void**)&old_gsm_ctor);
                LOGI("【成功】gsm 构造函数 Hook 已安装（RVA: 0x5f2de0c），等待密钥出现...");
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
