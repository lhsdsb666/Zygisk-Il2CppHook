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
    if (!file.is_open()) {
        LOGI("【汉化提示】未能打开字典文件！");
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

// ==================== 内存扫描：找韩文明文 ====================
//
// 目的：set_text 第一次收到韩文时，解密已经完成了，数据就在内存里。
// 做法：扫描 /proc/self/maps 列出的所有可读内存区域，
//       用 /proc/self/mem 读取内容，统计每块区域的韩文 UTF-8 字符密度，
//       把韩文密度高的区域整块保存下来。
// 结果：/sdcard/Download/memdump_N_XXXkb.bin
//       把这些文件发给 Claude，他来找出 kr.client 的明文。

static bool memory_scan_done = false;

void scan_memory_for_korean() {
    LOGI("【内存扫描】开始，遍历 /proc/self/maps ...");

    FILE* maps = fopen("/proc/self/maps", "r");
    FILE* mem_f = fopen("/proc/self/mem", "rb");
    if (!maps || !mem_f) {
        LOGI("【内存扫描】无法打开内存文件，放弃");
        if (maps) fclose(maps);
        if (mem_f) fclose(mem_f);
        return;
    }

    char line[512];
    int saved = 0;

    while (fgets(line, sizeof(line), maps)) {
        unsigned long start = 0, end = 0;
        char perms[8] = {0};
        char pathname[256] = {0};

        // 解析 maps 行：start-end perms offset dev inode [pathname]
        sscanf(line, "%lx-%lx %4s", &start, &end, perms);

        // 提取路径（最后一个空格后的内容）
        char* last_space = strrchr(line, ' ');
        if (last_space && last_space[1] != '\n' && last_space[1] != '\0') {
            strncpy(pathname, last_space + 1, sizeof(pathname) - 1);
            char* nl = strchr(pathname, '\n');
            if (nl) *nl = '\0';
        }

        // 只扫描可读区域
        if (perms[0] != 'r') continue;

        size_t size = end - start;

        // 跳过太小（<256KB）或太大（>80MB）的区域
        if (size < 256 * 1024 || size > 80 * 1024 * 1024) continue;

        // 跳过系统库映射：.so / .apk / /dev / [vdso] 等
        if (pathname[0] != '\0') {
            if (strstr(pathname, ".so") || strstr(pathname, ".apk") ||
                strstr(pathname, "/dev/") || strstr(pathname, "[vdso]") ||
                strstr(pathname, "[vsyscall]") || strstr(pathname, "dalvik-jit") ||
                strstr(pathname, "gralloc") || strstr(pathname, "ashmem"))
                continue;
        }

        // 读取内存块
        uint8_t* buf = (uint8_t*)malloc(size);
        if (!buf) continue;

        if (fseek(mem_f, (long)start, SEEK_SET) != 0) { free(buf); continue; }
        size_t read_n = fread(buf, 1, size, mem_f);
        if (read_n < 1024) { free(buf); continue; }

        // 统计韩文 UTF-8 三字节序列（EA-ED 80-BF 80-BF）
        int kr_count = 0;
        for (size_t i = 0; i + 2 < read_n; i++) {
            if (buf[i] >= 0xEA && buf[i] <= 0xED &&
                (buf[i+1] & 0xC0) == 0x80 &&
                (buf[i+2] & 0xC0) == 0x80) {
                kr_count++;
                i += 2; // 跳过已匹配的字节
            }
        }

        // 韩文密度：每 KB 有多少韩文字符
        float density = (float)kr_count / (read_n / 1024.0f);

        LOGI("【内存扫描】0x%08lx 大小=%zuKB 韩文=%d 密度=%.1f/KB [%s]",
             start, size / 1024, kr_count, density,
             pathname[0] ? pathname : "匿名");

        // 密度 > 每KB 1.5 个韩文字符 且总数 > 100，认为值得保存
        if (density > 1.5f && kr_count > 100) {
            char out[128];
            snprintf(out, sizeof(out),
                     "/sdcard/Download/memdump_%d_%zuKB.bin",
                     ++saved, size / 1024);
            FILE* f = fopen(out, "wb");
            if (f) {
                fwrite(buf, 1, read_n, f);
                fclose(f);
                LOGI("【内存扫描】★ 保存 %s（%d 个韩文字，密度 %.1f/KB）", out, kr_count, density);
            } else {
                LOGI("【内存扫描】写文件失败: %s", out);
            }
        }

        free(buf);
    }

    fclose(maps);
    fclose(mem_f);
    LOGI("【内存扫描】完成，共保存 %d 个区域到 /sdcard/Download/", saved);
}

static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;

void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string original_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);

        if (contains_korean(il2cpp_string->chars, il2cpp_string->length)) {
            // 第一次捕获到韩文时，立即启动内存扫描（后台线程，不阻塞渲染）
            if (!memory_scan_done) {
                memory_scan_done = true;
                LOGI("【内存扫描】触发！第一条韩文出现，启动后台扫描...");
                std::thread(scan_memory_for_korean).detach();
            }

            if (captured_kr_texts.find(original_text) == captured_kr_texts.end()) {
                captured_kr_texts.insert(original_text);
                FILE* f = fopen("/sdcard/Download/captured_korean.txt", "a");
                if (f != nullptr) {
                    std::string safe = original_text;
                    size_t p = 0;
                    while ((p = safe.find('\n', p)) != std::string::npos) { safe.replace(p, 1, "\\n"); p += 2; }
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
                    LOGI("【成功】il2cpp_string_new 绑定成功，地址：%p", il2cpp_string_new_ptr);
                } else {
                    LOGI("【错误】未能找到 il2cpp_string_new！");
                }
                load_translation_dict();

                void* set_text_addr = (void*)(il2cpp_base + 0xb670210);
                DobbyHook(set_text_addr, (void*)my_set_text, (void**)&old_set_text);
                LOGI("【成功】set_text Hook 完成，等待韩文触发内存扫描...");
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
