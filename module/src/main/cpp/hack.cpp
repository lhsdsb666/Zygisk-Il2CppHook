// Created by Perfare on 2020/7/4.
// 重构版：按名查找替代硬编码 RVA + MuMu 6 / Android 15 兼容修复
// 改动说明：
//   1. 调用已有的 il2cpp_api_init() 初始化全部 il2cpp API 函数指针
//   2. 用 il2cpp_class_from_name + il2cpp_class_get_method_from_name 按名查找 set_text，
//      替代硬编码 RVA（0xb670210），游戏更新后零维护
//   3. 移除 deob/deop hook（方法签名每次更新都变，且翻译功能不需要它们）
//   4. NativeBridge 部分套用 dumper 模块的 MuMu 6 修复（xDL 取代 dlopen）
//   5. x86 宿主 NativeBridge 失败时安全放弃，不再回退 hack_start

#include "hack.h"// Created by Perfare on 2020/7/4.
// 重构版：按名查找替代硬编码 RVA + MuMu 6 / Android 15 兼容修复
// 改动说明：
//   1. 调用已有的 il2cpp_api_init() 初始化全部 il2cpp API 函数指针
//   2. 用 il2cpp_class_from_name + il2cpp_class_get_method_from_name 按名查找 set_text，
//      替代硬编码 RVA（0xb670210），游戏更新后零维护
//   3. 移除 deob/deop hook（方法签名每次更新都变，且翻译功能不需要它们）
//   4. NativeBridge 部分套用 dumper 模块的 MuMu 6 修复（xDL 取代 dlopen）
//   5. x86 宿主 NativeBridge 失败时安全放弃，不再回退 hack_start
// 优化版新增：
//   6. 修复 install_crypto_dumps 缺前向声明的编译错误
//   7. 修复 UI.Text hook 复用 my_set_text 导致调用错误原函数（TMP 实现）的崩溃隐患
//   8. 解密 dump 内容哈希去重（内存 set + 跨重启文件存在检查），文件名携带 Key/长度
//      —— 为静态解包收集 (密文块, Key) 样本
//   9. 文本捕获与 dump 状态加锁（游戏多线程调用 set_text / 解密函数）
//  10. crypto hook 逐原语幂等（部分成功重试时不会对已 hook 地址二次 DobbyHook）

#include "hack.h"
#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include "il2cpp-class.h"
#include "il2cpp-tabledefs.h"

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
#include <mutex>
#include <sys/stat.h>
#include <limits.h>

extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// ==================== il2cpp API 外部声明（定义在 il2cpp_dump.cpp，由 il2cpp_api_init 初始化）====================
extern Il2CppDomain *(*il2cpp_domain_get)();
extern const Il2CppAssembly **(*il2cpp_domain_get_assemblies)(const Il2CppDomain *, size_t *);
extern const Il2CppImage *(*il2cpp_assembly_get_image)(const Il2CppAssembly *);
extern Il2CppClass *(*il2cpp_class_from_name)(const Il2CppImage *, const char *, const char *);
extern const MethodInfo *(*il2cpp_class_get_method_from_name)(Il2CppClass *, const char *, int);

// ==================== 基础工具函数 ====================

uintptr_t get_module_base(const char *module_name) {
    uintptr_t base = 0;
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
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

// ==================== 进程检查 ====================
// 只 hook 游戏主进程。子进程（形如 com.epidgames.trickcalrevive:gl）被注入
// exit blocker 后合法退出被卡死，是启动阶段闪退的主要原因之一
static bool is_main_game_process() {
    char cmdline[256] = {0};
    FILE *fp = fopen("/proc/self/cmdline", "rb");
    if (!fp) return true;  // 读不到则保守处理：继续 hook
    size_t n = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
    fclose(fp);
    if (n == 0) return true;
    std::string proc(cmdline);
    LOGI("【进程检查】cmdline = %s", proc.c_str());
    // 主进程 = 纯包名；子进程 = 包名:gl / 包名:push 等
    return proc.find(':') == std::string::npos;
}

// ==================== Hook 退出函数（防自杀）====================

static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;

void my_exit(int status) { LOGI("【Hook】Blocked exit(%d)!", status); while (true) { sleep(3600); } }
void my__exit(int status) { LOGI("【Hook】Blocked _exit(%d)!", status); while (true) { sleep(3600); } }

void hook_exit_functions() {
    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc != nullptr) {
        void *exit_sym = dlsym(libc, "exit");
        if (exit_sym) DobbyHook(exit_sym, (void *)my_exit, (void **)&old_exit);
        void *_exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) DobbyHook(_exit_sym, (void *)my__exit, (void **)&old__exit);
    }
    LOGI("【Hook】Exit blocker active.");
}

// ==================== TextMeshPro 文本拦截器 ====================

struct MyIl2CppString {
    void *klass;
    void *monitor;
    int32_t length;
    char16_t chars[0];
};

std::unordered_map<std::string, std::string> translation_map;
std::unordered_set<std::string> captured_kr_texts;
static std::mutex capture_mutex;  // set_text 可能被游戏多线程并发调用

static MyIl2CppString *(*il2cpp_string_new_ptr)(const char *str) = nullptr;

std::string utf16_to_utf8(const char16_t *utf16, int len) {
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
        else if (cp <= 0x7ff) { utf8 += (char)(0xc0 | (cp >> 6)); utf8 += (char)(0x80 | (cp & 0x3f)); }
        else if (cp <= 0xffff) { utf8 += (char)(0xe0 | (cp >> 12)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f)); }
        else { utf8 += (char)(0xf0 | (cp >> 18)); utf8 += (char)(0x80 | ((cp >> 12) & 0x3f)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f)); }
    }
    return utf8;
}

bool contains_korean(const char16_t *chars, int len) {
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
    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        // 跳过注释行
        if (line[0] == '#') continue;
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            translation_map[line.substr(0, pos)] = line.substr(pos + 1);
            count++;
        }
    }
    file.close();
    LOGI("【汉化提示】字典加载成功！共读入 %d 条翻译词条。", count);
}

// 启动时预加载已捕获的韩文，避免重启后重复写入
void preload_captured_texts() {
    std::string path = "/sdcard/Download/captured_korean.txt";
    std::ifstream file(path);
    if (!file.is_open()) {
        LOGI("【去重】抓取文件不存在，从头开始收集。");
        return;
    }
    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) {
            captured_kr_texts.insert(line);
            count++;
        }
    }
    file.close();
    LOGI("【去重】预加载了 %d 条已捕获文本，不会重复写入。", count);
}

// 第一次捕获到韩文时，打印调用栈
static bool callstack_printed = false;

using set_text_fn = void (*)(void *__this, MyIl2CppString *il2cpp_string);

static set_text_fn old_set_text = nullptr;      // TMP_Text.set_text 原函数
static set_text_fn old_ugi_set_text = nullptr;  // UnityEngine.UI.Text.set_text 原函数

// 公共处理：收集韩文原文 + 查字典翻译，最后必须调用“各自组件”的原函数。
// 注意：TMP_Text 与 UI.Text 是不同类，this 布局与实现不同，
// 绝不能把 UI.Text 的调用转发给 TMP_Text 的原函数（反之亦然），否则崩溃。
static void process_and_forward(void *__this, MyIl2CppString *il2cpp_string, set_text_fn origin) {
    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string original_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);

        if (contains_korean(il2cpp_string->chars, il2cpp_string->length)) {
            // 第一次捕获韩文时打印调用栈，辅助定位文本来源
            if (!callstack_printed) {
                callstack_printed = true;
                uintptr_t il2cpp_base = get_module_base("libil2cpp.so");
                void **fp = (void **)__builtin_frame_address(0);
                LOGI("【调用栈】==================");
                for (int i = 0; i < 30 && fp != nullptr; i++) {
                    uintptr_t ra = (uintptr_t)(*(fp + 1));
                    if (ra > il2cpp_base)
                        LOGI("【调用栈 %02d】RVA 0x%lx", i, (unsigned long)(ra - il2cpp_base));
                    void **next = (void **)(*fp);
                    if (next <= fp) break;
                    fp = next;
                }
                LOGI("【调用栈】==================");
            }

            // 自动收集未翻译的韩文原文（内存 set 去重 + 启动时预加载文件，双重防重复）
            bool is_new = false;
            {
                std::lock_guard<std::mutex> lk(capture_mutex);
                is_new = captured_kr_texts.insert(original_text).second;
            }
            if (is_new) {
                FILE *f = fopen("/sdcard/Download/captured_korean.txt", "a");
                if (f) {
                    std::string safe = original_text;
                    size_t p = 0;
                    while ((p = safe.find('\n', p)) != std::string::npos) {
                        safe.replace(p, 1, "\\n");
                        p += 2;
                    }
                    fprintf(f, "%s\n", safe.c_str());
                    fclose(f);
                }
                LOGI("【文本捕获】%s", original_text.c_str());  // 仅新捕获时打日志，避免刷屏
            }
        }

        // 查字典翻译
        auto it = translation_map.find(original_text);
        if (it != translation_map.end() && il2cpp_string_new_ptr != nullptr) {
            MyIl2CppString *new_string = il2cpp_string_new_ptr(it->second.c_str());
            if (new_string != nullptr) {
                LOGI("【汉化匹配】%s -> %s", original_text.c_str(), it->second.c_str());
                return origin(__this, new_string);
            }
        }
    }
    origin(__this, il2cpp_string);
}

void my_set_text(void *__this, MyIl2CppString *il2cpp_string) {
    process_and_forward(__this, il2cpp_string, old_set_text);
}

// legacy UI.Text 使用自己的替换函数，转发给自己的原函数
void my_ugi_set_text(void *__this, MyIl2CppString *il2cpp_string) {
    process_and_forward(__this, il2cpp_string, old_ugi_set_text);
}

// ==================== 按名查找并安装 Hook ====================

bool install_crypto_dumps();  // 前向声明：定义在下方解密 Dump 部分

// 通用文本方法查找+hook：在全部程序集中按 命名空间.类名.方法名 查找 1 个 string 参数的方法
static bool hook_text_method(const char *ns, const char *cls, const char *method_name,
                             void *replace_func, void **origin_func) {
    auto domain = il2cpp_domain_get();
    if (!domain) return false;
    size_t assembly_count = 0;
    const Il2CppAssembly **assemblies = il2cpp_domain_get_assemblies(domain, &assembly_count);
    if (!assemblies || assembly_count == 0) return false;

    for (size_t i = 0; i < assembly_count; i++) {
        const Il2CppImage *image = il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;
        Il2CppClass *klass = il2cpp_class_from_name(image, ns, cls);
        if (!klass) continue;
        const MethodInfo *method = il2cpp_class_get_method_from_name(klass, method_name, 1);
        if (!method || !method->methodPointer) {
            LOGE("【错误】找到 %s.%s 但 %s 方法指针为空", ns, cls, method_name);
            return false;
        }
        DobbyHook((void *)method->methodPointer, replace_func, origin_func);
        LOGI("【成功】%s.%s.%s Hook 完成（按名查找，地址 %p）", ns, cls, method_name, method->methodPointer);
        return true;
    }
    LOGI("【提示】未找到 %s.%s（该组件可能未使用）", ns, cls);
    return false;
}

// 返回 true 表示关键 hook（TMP 文本 + 解密 dump）全部就绪；可安全重试，已装的不会重装
bool install_hooks_by_name(void *handle) {
    static bool tmp_done = false;    // TextMeshPro 主路径
    static bool ugi_done = false;    // legacy uGUI Text（部分列表/旧UI使用）
    static bool crypto_done = false; // 解密函数 dump hook

    if (!tmp_done)
        tmp_done = hook_text_method("TMPro", "TMP_Text", "set_text",
                                    (void *)my_set_text, (void **)&old_set_text);
    if (!ugi_done)
        ugi_done = hook_text_method("UnityEngine.UI", "Text", "set_text",
                                    (void *)my_ugi_set_text, (void **)&old_ugi_set_text);

    if (ugi_done)
        LOGI("【成功】legacy UI.Text 附加 Hook 生效，覆盖更多文本组件。");

    if (!crypto_done)
        crypto_done = install_crypto_dumps();

    // crypto 依赖 Trickcal.AllShared 程序集就绪，未就绪时随重试循环补装
    return tmp_done && crypto_done;
}

// ==================== 剧情表解密 Dump（静态解包辅助）====================
// 原理：游戏用 Trickcal.AllShared.dll 的 res 类解密 .client 表文件（含剧情表 scenariotextkr）。
// 逆向 libil2cpp.so 确认：nrf/ewel/lqg 均为单字节 XOR 流密码：
//   out[i] = in[i] ^ key_byte(Index)   —— Key 随流位置 Index 推进
//   DecryptContext { int Key; int Hash; int Index; }
// hook 这三个函数，把解密后的明文 dump 到本地；文件名携带 Key 与内容哈希：
//   1. 同一块内容重复解密（重复加载同一张表）只落盘一次
//   2. (内容, Key) 样本可用于离线反推 Key 派生规律，实现静态解包

struct NativeDecryptContext {
    int32_t Key;
    int32_t Hash;
    int32_t Index;
};

static void (*old_nrf)(void *, int32_t, void *, int32_t, void *) = nullptr;
static void (*old_ewel)(void *, int32_t, void *, int32_t, void *) = nullptr;
static void (*old_lqg)(void *, int32_t, void *, int32_t, void *) = nullptr;

static const char *kDumpDir = "/sdcard/Download/ewel_dumps";
static const int kDumpMaxFiles = 20000;  // 安全上限，防极端情况刷爆存储

static std::mutex dump_mutex;                       // 解密可能发生在多线程
static std::unordered_set<uint64_t> dumped_hashes;  // 本轮已落盘内容
static int dump_count = 0;

// FNV-1a 64bit：快速内容指纹
static uint64_t fnv1a_hash(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; i++) { h ^= p[i]; h *= 0x100000001b3ULL; }
    return h;
}

// 解密完成后 dump 输出 span（a_ptr/a_len）
static void dump_decrypted(const char *func_name, void *a_ptr, int32_t a_len, NativeDecryptContext *ctx) {
    if (a_ptr == nullptr || a_len < 16) return;  // 跳过哈希块等小调用

    std::lock_guard<std::mutex> lk(dump_mutex);
    if (dump_count >= kDumpMaxFiles) return;

    uint64_t h = fnv1a_hash(a_ptr, (size_t)a_len);
    if (dumped_hashes.count(h)) return;  // 本轮已写过同样内容

    // 文件名: <函数>_key<Key>_len<长度>_<内容哈希>.bin
    char path[256];
    snprintf(path, sizeof(path), "%s/%s_key%08X_len%d_%016llX.bin",
             kDumpDir, func_name,
             (unsigned)(ctx ? (uint32_t)ctx->Key : 0), a_len, (unsigned long long)h);

    // 跨重启去重：上次运行已 dump 过同一块则跳过
    if (FILE *test = fopen(path, "rb")) { fclose(test); dumped_hashes.insert(h); return; }

    mkdir(kDumpDir, 0777);  // 已存在时返回 EEXIST，无碍
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(a_ptr, 1, (size_t)a_len, f);
        fclose(f);
        dumped_hashes.insert(h);
        dump_count++;
        if (dump_count <= 20 || dump_count % 200 == 0)
            LOGI("【解密Dump】#%d %s len=%d key=0x%08X -> %s",
                 dump_count, func_name, a_len, ctx ? ctx->Key : 0, path);
    }
}

void my_nrf(void *a_ptr, int32_t a_len, void *b_ptr, int32_t b_len, void *ctx) {
    old_nrf(a_ptr, a_len, b_ptr, b_len, ctx);
    dump_decrypted("nrf", a_ptr, a_len, (NativeDecryptContext *)ctx);
}

void my_ewel(void *a_ptr, int32_t a_len, void *b_ptr, int32_t b_len, void *ctx) {
    old_ewel(a_ptr, a_len, b_ptr, b_len, ctx);
    dump_decrypted("ewel", a_ptr, a_len, (NativeDecryptContext *)ctx);
}

void my_lqg(void *a_ptr, int32_t a_len, void *b_ptr, int32_t b_len, void *ctx) {
    old_lqg(a_ptr, a_len, b_ptr, b_len, ctx);
    dump_decrypted("lqg", a_ptr, a_len, (NativeDecryptContext *)ctx);
}

// 按名查找 res 类的三个解密原语并 hook（逐原语幂等：部分成功后重试只补装缺失的）
bool install_crypto_dumps() {
    static bool nrf_done = false, ewel_done = false, lqg_done = false;
    if (nrf_done && ewel_done && lqg_done) return true;

    auto domain = il2cpp_domain_get();
    if (!domain) return false;
    size_t assembly_count = 0;
    const Il2CppAssembly **assemblies = il2cpp_domain_get_assemblies(domain, &assembly_count);
    if (!assemblies || assembly_count == 0) return false;

    for (size_t i = 0; i < assembly_count; i++) {
        const Il2CppImage *image = il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;
        // res 类：全局命名空间，位于 Trickcal.AllShared.dll
        Il2CppClass *klass = il2cpp_class_from_name(image, "", "res");
        if (!klass) continue;

        LOGI("【解密Dump】找到 res 类，image=%p", image);
        struct { const char *name; void *replace; void **origin; bool *done; } prims[] = {
            {"nrf",  (void *)my_nrf,  (void **)&old_nrf,  &nrf_done},
            {"ewel", (void *)my_ewel, (void **)&old_ewel, &ewel_done},
            {"lqg",  (void *)my_lqg,  (void **)&old_lqg,  &lqg_done},
        };
        for (auto &p : prims) {
            if (*p.done) continue;  // 已装过，避免对同一地址二次 DobbyHook
            const MethodInfo *m = il2cpp_class_get_method_from_name(klass, p.name, 3);
            if (m && m->methodPointer) {
                DobbyHook((void *)m->methodPointer, p.replace, p.origin);
                *p.done = true;
                LOGI("【成功】res.%s Hook 完成（地址 %p）", p.name, m->methodPointer);
            } else {
                LOGE("【错误】res.%s 方法查找失败", p.name);
            }
        }
        if (nrf_done && ewel_done && lqg_done) {
            LOGI("【解密Dump】表解密拦截已激活，运行游戏加载任意界面后检查 %s/", kDumpDir);
            return true;
        }
        // res 已找到但方法未找全：res 类唯一，无需继续遍历其它程序集
        return false;
    }
    return false;
}

// ==================== 主入口 ====================

void hack_start(const char *game_data_dir) {
    // 只 hook 游戏主进程：子进程（:gl 等）注入 exit blocker 会导致启动阶段闪退
    if (!is_main_game_process()) {
        LOGI("【跳过】非主进程，不注入 hook。");
        return;
    }

    LOGI("hack_start inside, waiting for libil2cpp.so...");

    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            LOGI("【成功】libil2cpp.so 已加载，handle=%p", handle);

            // 防自杀：hook exit/_exit
            hook_exit_functions();

            // 初始化全部 il2cpp API + domain + 线程 attach
            il2cpp_api_init(handle);

            // 一次性任务：绑定字符串创建函数
            size_t sym_size = 0;
            il2cpp_string_new_ptr = (MyIl2CppString *(*)(const char *))xdl_sym(handle, "il2cpp_string_new", &sym_size);
            if (il2cpp_string_new_ptr != nullptr)
                LOGI("【成功】il2cpp_string_new 绑定 %p", il2cpp_string_new_ptr);
            else
                LOGI("【错误】未能绑定 il2cpp_string_new");

            // 一次性任务：加载翻译字典 + 预加载已捕获文本（去重）
            load_translation_dict();
            preload_captured_texts();

            // hook 安装带重试：启动早期 il2cpp 程序集可能尚未加载完毕
            bool hooked = false;
            for (int retry = 0; retry < 15 && !hooked; retry++) {
                hooked = install_hooks_by_name(handle);
                if (!hooked) {
                    LOGI("【重试】il2cpp 程序集未就绪，第 %d/15 次重试...", retry + 1);
                    sleep(2);
                }
            }
            if (!hooked)
                LOGE("【错误】多次重试后仍未完成 hook 安装。");

            break;
        }
        sleep(1);
    }
}

// ==================== 模拟器环境兼容代码（MuMu 6 / Android 15 修复版）====================
// 与 dumper 模块相同的修复：
//   1. xDL 取代 dlopen("libart.so")，绕过 Android 15 命名空间限制
//   2. xDL 取代 dlopen("libhoudini.so"/"libnb.so")，直接从内存取 NativeBridgeItf
//   3. 拿不到 JavaVM 时不崩溃，继续走 NativeBridge 路线
//   4. loadLibraryExt 失败自动回退 loadLibrary
//   5. x86 宿主 NativeBridge 失败时安全放弃

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                 "currentApplication",
                                                                 "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                   "getApplicationInfo",
                                                                   "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
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
    // 等待 houdini 初始化
    sleep(5);

    // Android 15 上 dlopen("libart.so") 会被命名空间拦截，dlsym 返回空指针
    // xDL 直接从 /proc/self/maps 中找到已加载的 libart.so 并解析符号
    auto libart = xdl_open("libart.so", 0);

    size_t sym_size = 0;
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *))(libart ? xdl_sym(libart,
                                                                                         "JNI_GetCreatedJavaVMs",
                                                                                         &sym_size)
                                                                               : nullptr);

    if (!JNI_GetCreatedJavaVMs) {
        JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *))dlsym(RTLD_DEFAULT,
                                                                            "JNI_GetCreatedJavaVMs");
    }

    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);

    JavaVM *vms_buf[1];
    JavaVM *vms = nullptr;
    jsize num_vms = 0;

    if (JNI_GetCreatedJavaVMs) {
        jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
        if (status == JNI_OK && num_vms > 0) {
            vms = vms_buf[0];
        }
    }

    if (vms) {
        auto lib_dir = GetLibDir(vms);
        if (!lib_dir.empty()) {
            if (lib_dir.find("/lib/x86") != std::string::npos) {
                LOGI("no need NativeBridge");
                munmap(data, length);
                hack_start(game_data_dir);
                return true;
            }
        } else {
            LOGE("GetLibDir error, continue with NativeBridge");
        }
    } else {
        // 拿不到 JavaVM 不崩溃：目标游戏为 ARM-only，继续尝试 NativeBridge
        LOGE("GetCreatedJavaVMs error, continue with NativeBridge");
    }

    // Android 15 上 dlopen libhoudini.so/libnb.so 也会被命名空间拦截
    // 但转译器初始化时它们已经被加载进本进程，用 xDL 直接从内存取 NativeBridgeItf
    NativeBridgeCallbacks *callbacks = nullptr;

    const char *nb_names[] = {"libnb.so", "libhoudini.so"};
    for (auto nb_name : nb_names) {
        auto nb = xdl_open(nb_name, 0);
        if (!nb) continue;

        LOGI("nb %s found in maps", nb_name);

        size_t itf_size = 0;
        callbacks = (NativeBridgeCallbacks *)xdl_sym(nb, "NativeBridgeItf", &itf_size);
        break;
    }

    if (!callbacks) {
        // 兜底：老方法 dlopen + dlsym（旧版模拟器仍可用）
        auto nb = dlopen("libhoudini.so", RTLD_NOW);
        if (!nb) {
            auto native_bridge = std::array<char, PROP_VALUE_MAX>();
            __system_property_get("ro.dalvik.vm.native.bridge", native_bridge.data());
            LOGI("native bridge: %s", native_bridge.data());
            nb = dlopen(native_bridge.data(), RTLD_NOW);
        }
        if (!nb) {
            LOGE("dlopen native bridge failed");
            return false;
        }
        LOGI("nb %p", nb);
        callbacks = (NativeBridgeCallbacks *)dlsym(nb, "NativeBridgeItf");
    }

    if (!callbacks) {
        LOGE("NativeBridgeItf not found");
        return false;
    }

    LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
    LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
    LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

    int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
    ftruncate(fd, (off_t)length);
    void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
    memcpy(mem, data, length);
    munmap(mem, length);
    munmap(data, length);

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
    LOGI("arm path %s", path);

    void *arm_handle = nullptr;
    if (api_level >= 26) {
        arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *)3);
        if (!arm_handle) {
            LOGE("loadLibraryExt failed, try loadLibrary");
            arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
        }
    } else {
        arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
    }

    if (arm_handle) {
        LOGI("arm handle %p", arm_handle);
        auto init = (void (*)(JavaVM *, void *))callbacks->getTrampoline(arm_handle,
                                                                         "JNI_OnLoad",
                                                                         nullptr, 0);
        LOGI("JNI_OnLoad %p", init);
        if (init) {
            init(vms, (void *)game_data_dir);
            return true;
        }
        LOGE("getTrampoline JNI_OnLoad failed");
    } else {
        LOGE("load arm so failed");
    }

    close(fd);
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    // 子进程不注入（避免 NativeBridge 加载 + exit blocker 干扰游戏子进程）
    if (!is_main_game_process()) {
        LOGI("【跳过】非主进程，跳过注入。");
        return;
    }

    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        // x86 宿主 NativeBridge 失败时安全放弃，不回退 hack_start（否则在 x86 上下文调用 ARM 代码会闪退）
        LOGE("NativeBridgeLoad failed, skip dump");
        return;
    }
#else
    hack_start(game_data_dir);
#endif
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *)reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif

#include "il2cpp_dump.h"
#include "log.h"
#include "xdl.h"
#include "il2cpp-class.h"
#include "il2cpp-tabledefs.h"

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

// ==================== il2cpp API 外部声明（定义在 il2cpp_dump.cpp，由 il2cpp_api_init 初始化）====================
extern Il2CppDomain *(*il2cpp_domain_get)();
extern const Il2CppAssembly **(*il2cpp_domain_get_assemblies)(const Il2CppDomain *, size_t *);
extern const Il2CppImage *(*il2cpp_assembly_get_image)(const Il2CppAssembly *);
extern Il2CppClass *(*il2cpp_class_from_name)(const Il2CppImage *, const char *, const char *);
extern const MethodInfo *(*il2cpp_class_get_method_from_name)(Il2CppClass *, const char *, int);

// ==================== 基础工具函数 ====================

uintptr_t get_module_base(const char *module_name) {
    uintptr_t base = 0;
    char line[512];
    FILE *fp = fopen("/proc/self/maps", "r");
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

// ==================== Hook 退出函数（防自杀）====================

static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;

void my_exit(int status) { LOGI("【Hook】Blocked exit(%d)!", status); while (true) { sleep(3600); } }
void my__exit(int status) { LOGI("【Hook】Blocked _exit(%d)!", status); while (true) { sleep(3600); } }

void hook_exit_functions() {
    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc != nullptr) {
        void *exit_sym = dlsym(libc, "exit");
        if (exit_sym) DobbyHook(exit_sym, (void *)my_exit, (void **)&old_exit);
        void *_exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) DobbyHook(_exit_sym, (void *)my__exit, (void **)&old__exit);
    }
    LOGI("【Hook】Exit blocker active.");
}

// ==================== TextMeshPro 文本拦截器 ====================

struct MyIl2CppString {
    void *klass;
    void *monitor;
    int32_t length;
    char16_t chars[0];
};

std::unordered_map<std::string, std::string> translation_map;
std::unordered_set<std::string> captured_kr_texts;

static MyIl2CppString *(*il2cpp_string_new_ptr)(const char *str) = nullptr;

std::string utf16_to_utf8(const char16_t *utf16, int len) {
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
        else if (cp <= 0x7ff) { utf8 += (char)(0xc0 | (cp >> 6)); utf8 += (char)(0x80 | (cp & 0x3f)); }
        else if (cp <= 0xffff) { utf8 += (char)(0xe0 | (cp >> 12)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f)); }
        else { utf8 += (char)(0xf0 | (cp >> 18)); utf8 += (char)(0x80 | ((cp >> 12) & 0x3f)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f)); }
    }
    return utf8;
}

bool contains_korean(const char16_t *chars, int len) {
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

// 第一次捕获到韩文时，打印调用栈
static bool callstack_printed = false;

static void (*old_set_text)(void *__this, MyIl2CppString *il2cpp_string) = nullptr;

void my_set_text(void *__this, MyIl2CppString *il2cpp_string) {
    if (il2cpp_string != nullptr && il2cpp_string->length > 0) {
        std::string original_text = utf16_to_utf8(il2cpp_string->chars, il2cpp_string->length);

        if (contains_korean(il2cpp_string->chars, il2cpp_string->length)) {
            // 第一次捕获韩文时打印调用栈，辅助定位文本来源
            if (!callstack_printed) {
                callstack_printed = true;
                uintptr_t il2cpp_base = get_module_base("libil2cpp.so");
                void **fp = (void **)__builtin_frame_address(0);
                LOGI("【调用栈】==================");
                for (int i = 0; i < 30 && fp != nullptr; i++) {
                    uintptr_t ra = (uintptr_t)(*(fp + 1));
                    if (ra > il2cpp_base)
                        LOGI("【调用栈 %02d】RVA 0x%lx", i, (unsigned long)(ra - il2cpp_base));
                    void **next = (void **)(*fp);
                    if (next <= fp) break;
                    fp = next;
                }
                LOGI("【调用栈】==================");
            }

            // 自动收集未翻译的韩文原文
            if (captured_kr_texts.find(original_text) == captured_kr_texts.end()) {
                captured_kr_texts.insert(original_text);
                FILE *f = fopen("/sdcard/Download/captured_korean.txt", "a");
                if (f) {
                    std::string safe = original_text;
                    size_t p = 0;
                    while ((p = safe.find('\n', p)) != std::string::npos) {
                        safe.replace(p, 1, "\\n");
                        p += 2;
                    }
                    fprintf(f, "%s\n", safe.c_str());
                    fclose(f);
                }
            }
        }

        // 查字典翻译
        auto it = translation_map.find(original_text);
        if (it != translation_map.end()) {
            if (il2cpp_string_new_ptr != nullptr) {
                MyIl2CppString *new_string = il2cpp_string_new_ptr(it->second.c_str());
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

// ==================== 按名查找并安装 Hook ====================

void install_hooks_by_name(void *handle) {
    // 绑定 il2cpp_string_new（用于创建替换字符串）
    size_t sym_size = 0;
    il2cpp_string_new_ptr = (MyIl2CppString *(*)(const char *))xdl_sym(handle, "il2cpp_string_new", &sym_size);
    if (il2cpp_string_new_ptr != nullptr)
        LOGI("【成功】il2cpp_string_new 绑定 %p", il2cpp_string_new_ptr);
    else
        LOGI("【错误】未能绑定 il2cpp_string_new");

    // 加载翻译字典
    load_translation_dict();

    // ====== 按名查找 TMP_Text.set_text ======
    // 原理：il2cpp_class_from_name(image, 命名空间, 类名) → 拿到 class
    //       il2cpp_class_get_method_from_name(class, 方法名, 参数个数) → 拿到 MethodInfo
    //       method->methodPointer 就是函数地址，不需要任何 RVA
    // TMP_Text 是 Unity 框架类，类名/方法名永远不会因游戏更新而改变

    auto domain = il2cpp_domain_get();
    if (!domain) {
        LOGE("【错误】il2cpp_domain_get 返回 null，无法按名查找");
        return;
    }
    LOGI("【按名查找】domain = %p", domain);

    size_t assembly_count = 0;
    const Il2CppAssembly **assemblies = il2cpp_domain_get_assemblies(domain, &assembly_count);
    if (!assemblies || assembly_count == 0) {
        LOGE("【错误】无法获取程序集列表");
        return;
    }
    LOGI("【按名查找】共 %zu 个程序集", assembly_count);

    bool set_text_hooked = false;

    for (size_t i = 0; i < assembly_count && !set_text_hooked; i++) {
        const Il2CppImage *image = il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;

        // 尝试在当前 image 中查找 TMPro.TMP_Text 类
        Il2CppClass *klass = il2cpp_class_from_name(image, "TMPro", "TMP_Text");
        if (!klass) continue;

        LOGI("【按名查找】找到 TMP_Text 类，image=%p", image);

        // 查找 set_text 方法（1 个参数：String value）
        const MethodInfo *method = il2cpp_class_get_method_from_name(klass, "set_text", 1);
        if (!method || !method->methodPointer) {
            LOGE("【错误】找到 TMP_Text 但 set_text 方法指针为空");
            continue;
        }

        void *set_text_addr = (void *)method->methodPointer;
        DobbyHook(set_text_addr, (void *)my_set_text, (void **)&old_set_text);
        LOGI("【成功】set_text Hook 完成（按名查找，地址 %p）", set_text_addr);
        set_text_hooked = true;
    }

    if (!set_text_hooked) {
        LOGE("【错误】未能按名查找并 hook set_text。可能原因：il2cpp 未完成初始化或类名不匹配。");
    }
}

// ==================== 主入口 ====================

void hack_start(const char *game_data_dir) {
    LOGI("hack_start inside, waiting for libil2cpp.so...");

    for (int i = 0; i < 300; i++) {
        void *handle = xdl_open("libil2cpp.so", 0);
        if (handle) {
            LOGI("【成功】libil2cpp.so 已加载，handle=%p", handle);

            // 防自杀：hook exit/_exit
            hook_exit_functions();

            // ★ 关键改动：调用已有的 il2cpp_api_init() 初始化全部 API + domain + 线程 attach
            // il2cpp_api_init 内部会：
            //   1. init_il2cpp_api(handle) → 通过 xdl_sym 绑定全部 il2cpp API 函数指针
            //   2. 等待 il2cpp_is_vm_thread 返回 true（运行时就绪）
            //   3. il2cpp_domain_get() + il2cpp_thread_attach(domain)
            il2cpp_api_init(handle);

            // ★ 按名查找并安装所有 Hook（替代硬编码 RVA）
            install_hooks_by_name(handle);

            break;
        }
        sleep(1);
    }
}

// ==================== 模拟器环境兼容代码（MuMu 6 / Android 15 修复版）====================
// 与 dumper 模块相同的修复：
//   1. xDL 取代 dlopen("libart.so")，绕过 Android 15 命名空间限制
//   2. xDL 取代 dlopen("libhoudini.so"/"libnb.so")，直接从内存取 NativeBridgeItf
//   3. 拿不到 JavaVM 时不崩溃，继续走 NativeBridge 路线
//   4. loadLibraryExt 失败自动回退 loadLibrary
//   5. x86 宿主 NativeBridge 失败时安全放弃

std::string GetLibDir(JavaVM *vms) {
    JNIEnv *env = nullptr;
    vms->AttachCurrentThread(&env, nullptr);
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplicationId = env->GetStaticMethodID(activity_thread_clz,
                                                                 "currentApplication",
                                                                 "()Landroid/app/Application;");
        if (currentApplicationId) {
            jobject application = env->CallStaticObjectMethod(activity_thread_clz,
                                                              currentApplicationId);
            jclass application_clazz = env->GetObjectClass(application);
            if (application_clazz) {
                jmethodID get_application_info = env->GetMethodID(application_clazz,
                                                                   "getApplicationInfo",
                                                                   "()Landroid/content/pm/ApplicationInfo;");
                if (get_application_info) {
                    jobject application_info = env->CallObjectMethod(application,
                                                                     get_application_info);
                    jfieldID native_library_dir_id = env->GetFieldID(
                            env->GetObjectClass(application_info), "nativeLibraryDir",
                            "Ljava/lang/String;");
                    if (native_library_dir_id) {
                        auto native_library_dir_jstring = (jstring) env->GetObjectField(
                                application_info, native_library_dir_id);
                        auto path = env->GetStringUTFChars(native_library_dir_jstring, nullptr);
                        LOGI("lib dir %s", path);
                        std::string lib_dir(path);
                        env->ReleaseStringUTFChars(native_library_dir_jstring, path);
                        return lib_dir;
                    } else {
                        LOGE("nativeLibraryDir not found");
                    }
                } else {
                    LOGE("getApplicationInfo not found");
                }
            } else {
                LOGE("application class not found");
            }
        } else {
            LOGE("currentApplication not found");
        }
    } else {
        LOGE("ActivityThread not found");
    }
    return {};
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
    // 等待 houdini 初始化
    sleep(5);

    // Android 15 上 dlopen("libart.so") 会被命名空间拦截，dlsym 返回空指针
    // xDL 直接从 /proc/self/maps 中找到已加载的 libart.so 并解析符号
    auto libart = xdl_open("libart.so", 0);

    size_t sym_size = 0;
    auto JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *))(libart ? xdl_sym(libart,
                                                                                         "JNI_GetCreatedJavaVMs",
                                                                                         &sym_size)
                                                                               : nullptr);

    if (!JNI_GetCreatedJavaVMs) {
        JNI_GetCreatedJavaVMs = (jint (*)(JavaVM **, jsize, jsize *))dlsym(RTLD_DEFAULT,
                                                                            "JNI_GetCreatedJavaVMs");
    }

    LOGI("JNI_GetCreatedJavaVMs %p", JNI_GetCreatedJavaVMs);

    JavaVM *vms_buf[1];
    JavaVM *vms = nullptr;
    jsize num_vms = 0;

    if (JNI_GetCreatedJavaVMs) {
        jint status = JNI_GetCreatedJavaVMs(vms_buf, 1, &num_vms);
        if (status == JNI_OK && num_vms > 0) {
            vms = vms_buf[0];
        }
    }

    if (vms) {
        auto lib_dir = GetLibDir(vms);
        if (!lib_dir.empty()) {
            if (lib_dir.find("/lib/x86") != std::string::npos) {
                LOGI("no need NativeBridge");
                munmap(data, length);
                hack_start(game_data_dir);
                return true;
            }
        } else {
            LOGE("GetLibDir error, continue with NativeBridge");
        }
    } else {
        // 拿不到 JavaVM 不崩溃：目标游戏为 ARM-only，继续尝试 NativeBridge
        LOGE("GetCreatedJavaVMs error, continue with NativeBridge");
    }

    // Android 15 上 dlopen libhoudini.so/libnb.so 也会被命名空间拦截
    // 但转译器初始化时它们已经被加载进本进程，用 xDL 直接从内存取 NativeBridgeItf
    NativeBridgeCallbacks *callbacks = nullptr;

    const char *nb_names[] = {"libnb.so", "libhoudini.so"};
    for (auto nb_name : nb_names) {
        auto nb = xdl_open(nb_name, 0);
        if (!nb) continue;

        LOGI("nb %s found in maps", nb_name);

        size_t itf_size = 0;
        callbacks = (NativeBridgeCallbacks *)xdl_sym(nb, "NativeBridgeItf", &itf_size);
        break;
    }

    if (!callbacks) {
        // 兜底：老方法 dlopen + dlsym（旧版模拟器仍可用）
        auto nb = dlopen("libhoudini.so", RTLD_NOW);
        if (!nb) {
            auto native_bridge = std::array<char, PROP_VALUE_MAX>();
            __system_property_get("ro.dalvik.vm.native.bridge", native_bridge.data());
            LOGI("native bridge: %s", native_bridge.data());
            nb = dlopen(native_bridge.data(), RTLD_NOW);
        }
        if (!nb) {
            LOGE("dlopen native bridge failed");
            return false;
        }
        LOGI("nb %p", nb);
        callbacks = (NativeBridgeCallbacks *)dlsym(nb, "NativeBridgeItf");
    }

    if (!callbacks) {
        LOGE("NativeBridgeItf not found");
        return false;
    }

    LOGI("NativeBridgeLoadLibrary %p", callbacks->loadLibrary);
    LOGI("NativeBridgeLoadLibraryExt %p", callbacks->loadLibraryExt);
    LOGI("NativeBridgeGetTrampoline %p", callbacks->getTrampoline);

    int fd = syscall(__NR_memfd_create, "anon", MFD_CLOEXEC);
    ftruncate(fd, (off_t)length);
    void *mem = mmap(nullptr, length, PROT_WRITE, MAP_SHARED, fd, 0);
    memcpy(mem, data, length);
    munmap(mem, length);
    munmap(data, length);

    char path[PATH_MAX];
    snprintf(path, PATH_MAX, "/proc/self/fd/%d", fd);
    LOGI("arm path %s", path);

    void *arm_handle = nullptr;
    if (api_level >= 26) {
        arm_handle = callbacks->loadLibraryExt(path, RTLD_NOW, (void *)3);
        if (!arm_handle) {
            LOGE("loadLibraryExt failed, try loadLibrary");
            arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
        }
    } else {
        arm_handle = callbacks->loadLibrary(path, RTLD_NOW);
    }

    if (arm_handle) {
        LOGI("arm handle %p", arm_handle);
        auto init = (void (*)(JavaVM *, void *))callbacks->getTrampoline(arm_handle,
                                                                         "JNI_OnLoad",
                                                                         nullptr, 0);
        LOGI("JNI_OnLoad %p", init);
        if (init) {
            init(vms, (void *)game_data_dir);
            return true;
        }
        LOGE("getTrampoline JNI_OnLoad failed");
    } else {
        LOGE("load arm so failed");
    }

    close(fd);
    return false;
}

void hack_prepare(const char *game_data_dir, void *data, size_t length) {
    LOGI("hack thread: %d", gettid());
    int api_level = android_get_device_api_level();
    LOGI("api level: %d", api_level);

#if defined(__i386__) || defined(__x86_64__)
    if (!NativeBridgeLoad(game_data_dir, api_level, data, length)) {
        // x86 宿主 NativeBridge 失败时安全放弃，不回退 hack_start（否则在 x86 上下文调用 ARM 代码会闪退）
        LOGE("NativeBridgeLoad failed, skip dump");
        return;
    }
#else
    hack_start(game_data_dir);
#endif
}

#if defined(__arm__) || defined(__aarch64__)
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *)reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
