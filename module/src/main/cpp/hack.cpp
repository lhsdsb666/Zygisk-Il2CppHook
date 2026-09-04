// Created by Perfare on 2020/7/4.
// Trickcal Revive 汉化模块（重构维护版，2026-09-04 精简）
//
// 当前只保留三条活路径（实验性解密 dump / 加解密探针 / 枚举类查找已全部删除：
// 热更新后剧情装载原生侧化，托管层加解密探针实测全程零触发，留着只增崩溃面）：
//   1. 文本翻译：按名 hook TMPro.TMP_Text.set_text 与 UnityEngine.UI.Text.set_text
//      （il2cpp_class_from_name 按名查找，不硬编码 RVA，游戏更新零维护），
//      查 string_data.txt 字典把韩文替换为中文。
//   2. 韩文采集：set_text 钩子 + il2cpp_string_new / il2cpp_string_new_utf16
//      全量捕获网。任何托管字符串（含原生 AssetBundle 反序列化直接构造的）
//      创建时若含谚文，一律去重落盘 captured_korean.txt，供离线批量翻译。
//      注意：hook 的是导出跳板解析出的【真实实现】，见 resolve_thunk_target()。
//   3. 防自杀：hook exit/_exit/kill/tgkill，拦截启动完整性检测的自毁。
//
// 血的教训：Dobby arm64 内联补丁占 16 字节。il2cpp 导出常是 4~8 字节 B/BL 跳板
//   且彼此相邻（实测 string_new 与 _utf16 相隔仅 8 字节），直接对导出地址
//   hook 会互相覆盖补丁 → 游戏黑屏卡死。必须解析跳板到真实实现、校验目标间距
//   ≥32 字节、确认未被 hook 过再安装。
//
// 兼容：MuMu/x86 宿主走 NativeBridge（xDL 取 NativeBridgeItf），Android 15 修复；
//   子进程不注入；x86 NativeBridge 失败时安全放弃。

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

#include <signal.h>

static void (*old_exit)(int status) = nullptr;
static void (*old__exit)(int status) = nullptr;
static int (*old_kill)(pid_t, int) = nullptr;
static int (*old_tgkill)(int, int, int) = nullptr;

void my_exit(int status) { LOGI("【Hook】Blocked exit(%d)!", status); while (true) { sleep(3600); } }
void my__exit(int status) { LOGI("【Hook】Blocked _exit(%d)!", status); while (true) { sleep(3600); } }

// 拦截针对自身的 SIGKILL：游戏启动完整性检测失败时通过 kill(getpid(), SIGKILL)
// 静默自杀（无崩溃日志）。仅拦截 SIGKILL 且目标是本进程，其余信号照常透传。
static int my_kill(pid_t pid, int sig) {
    if (sig == SIGKILL && pid == getpid()) {
        LOGI("【Hook】Blocked self-kill(SIGKILL)!");
        return 0;
    }
    return old_kill(pid, sig);
}

static int my_tgkill(int tgid, int tid, int sig) {
    if (sig == SIGKILL && tgid == getpid()) {
        LOGI("【Hook】Blocked self-tgkill(SIGKILL)!");
        return 0;
    }
    return old_tgkill(tgid, tid, sig);
}

void hook_exit_functions() {
    void *libc = dlopen("libc.so", RTLD_NOW | RTLD_GLOBAL);
    if (libc != nullptr) {
        void *exit_sym = dlsym(libc, "exit");
        if (exit_sym) DobbyHook(exit_sym, (void *)my_exit, (void **)&old_exit);
        void *_exit_sym = dlsym(libc, "_exit");
        if (_exit_sym) DobbyHook(_exit_sym, (void *)my__exit, (void **)&old__exit);
        void *kill_sym = dlsym(libc, "kill");
        if (kill_sym) DobbyHook(kill_sym, (void *)my_kill, (void **)&old_kill);
        void *tgkill_sym = dlsym(libc, "tgkill");
        if (tgkill_sym) DobbyHook(tgkill_sym, (void *)my_tgkill, (void **)&old_tgkill);
    }
    LOGI("【Hook】Exit blocker + self-SIGKILL blocker active.");
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

// 字典文件中的换行以字面 "\n" 转义存储（一行一条），而游戏字符串含真实换行，
// 加载时必须还原，否则含换行的词条永远匹配不上
static std::string unescape_newlines(std::string s) {
    size_t p = 0;
    while ((p = s.find("\\n", p)) != std::string::npos) {
        s.replace(p, 2, "\n");
        p += 1;
    }
    return s;
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
            translation_map[unescape_newlines(line.substr(0, pos))] = unescape_newlines(line.substr(pos + 1));
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

// 公共记录：一条韩文原文 → 内存去重 + 追加写 captured_korean.txt（线程安全）。
// set_text 路径与全量字符串捕获网共用，is_new 时打日志（限流）。
static bool record_captured_korean(const char16_t *chars, int32_t len, const char *tag) {
    // len>=1：单音节韩文（네/예/응 等）也是有效文本；>1024 视为非文本载荷跳过
    if (!chars || len <= 0 || len > 1024) return false;
    if (!contains_korean(chars, len)) return false;
    std::string text = utf16_to_utf8(chars, len);
    bool is_new = false;
    {
        std::lock_guard<std::mutex> lk(capture_mutex);
        is_new = captured_kr_texts.insert(text).second;
    }
    if (!is_new) return false;
    FILE *f = fopen("/sdcard/Download/captured_korean.txt", "a");
    if (f) {
        std::string safe = text;
        size_t p = 0;
        while ((p = safe.find('\n', p)) != std::string::npos) {
            safe.replace(p, 1, "\\n");
            p += 2;
        }
        fprintf(f, "%s\n", safe.c_str());
        fclose(f);
    }
    static int total = 0;
    int n = ++total;
    if (n <= 100 || n % 500 == 0)
        LOGI("【%s】#%d %s", tag, n, text.c_str());
    return true;
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
            record_captured_korean(il2cpp_string->chars, il2cpp_string->length, "文本捕获");
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

// ==================== 全量韩文捕获网（版本无关，2026-09-04）====================
// 背景：热更新后剧情数据不再经过 TextAsset.bytes / mscorlib 加密通道（原生
// AssetBundle/热更文件反序列化直接构造托管字符串），按类名找解密器已无意义。
// 但任何托管字符串最终都要经 il2cpp_string_new / il2cpp_string_new_utf16 创建。
// 在这里拦一道：凡是含韩文的字符串一律入库 captured_korean.txt，覆盖
// “已加载但未显示”的文本（未走分支的剧情、全部图鉴/物品/技能描述等），
// 不依赖任何类名/方法名，游戏再更新也有效。
using string_new_fn     = MyIl2CppString *(*)(const char *utf8);
using string_new_u16_fn = MyIl2CppString *(*)(const char16_t *utf16, int32_t len);
static string_new_fn     old_string_new = nullptr;
static string_new_u16_fn old_string_new_utf16 = nullptr;

// ---- Dobby 安全护栏（2026-09-04 黑屏事故修复）----
// 事故根因：il2cpp_string_new 与 il2cpp_string_new_utf16 两个导出在 libil2cpp
// 中只是 4~8 字节的 B/BL 跳板，相邻仅 8 字节（实测 0x...36bc / 0x...36c4）；
// Dobby 的 arm64 内联补丁占 16 字节（LDR Xn,[pc,#8]; BR Xn; .quad），直接对
// 导出地址 hook 会互相覆盖：第二个钩子的 trampoline 把跳转数据当指令执行，
// 游戏启动后第一次创建 UTF-16 字符串即卡死黑屏。
// 解法：hook 前先沿 B/BL 跳板解析出【真实实现函数】再 hook（真实函数体大、
// 间距充足，且 il2cpp 内部直接调用真实实现的路径也一并被覆盖）。

// 若函数入口是 B/BL 跳转且目标落在 libil2cpp.so 范围内，返回跳转目标；否则原样返回
static void *resolve_thunk_target(void *sym, uintptr_t base) {
    if (!sym) return nullptr;
    uint32_t w = *(volatile uint32_t *)sym;
    uint32_t op = w & 0xFC000000;
    if (op == 0x14000000 || op == 0x94000000) {  // B(000101) / BL(100101)
        int32_t imm = (int32_t)(w & 0x03FFFFFF);
        if (imm & 0x02000000) imm |= (int32_t)0xFC000000;  // 26 位立即数符号扩展
        uintptr_t target = (uintptr_t)sym + (int64_t)imm * 4;
        if (base != 0 && target > base && target < base + 0x10000000ULL) {
            LOGI("【韩文库】%p 为 B/BL 跳板，解析到真实实现 %p", sym, (void *)target);
            return (void *)target;
        }
        LOGI("【韩文库】%p 跳板目标 %p 超出 libil2cpp 范围，按原地址处理", sym, (void *)target);
    }
    return sym;
}

// 入口是否已是 Dobby 绝对跳转桩（LDR Xt,[pc,#8] 后接 BR Xn），防止重复 hook
static bool already_dobby_patched(void *p) {
    if (!p) return false;
    volatile uint32_t *w = (volatile uint32_t *)p;
    bool ldr_lit = (w[0] & 0xFC000000) == 0x58000000;  // LDR (literal)
    bool br_xn   = (w[1] & 0xFFFFFC1F) == 0xD61F0000;  // BR Xn
    return ldr_lit && br_xn;
}

static void net_capture_result(MyIl2CppString *s) {
    // s 是运行时刚构造返回的字符串对象，null 判断即可；长度字段按
    // IL2CPP 字符串布局（length@0x10）读取，record 内部另有长度上下限校验
    if (!s) return;
    record_captured_korean(s->chars, s->length, "文本网");
}

static MyIl2CppString *my_string_new(const char *utf8) {
    MyIl2CppString *r = old_string_new(utf8);
    net_capture_result(r);
    return r;
}

static MyIl2CppString *my_string_new_utf16(const char16_t *utf16, int32_t len) {
    MyIl2CppString *r = old_string_new_utf16(utf16, len);
    net_capture_result(r);
    return r;
}

// ==================== 按名查找并安装 Hook ====================

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

// 返回 true 表示关键文本 hook（TMP 主路径）已就绪；可安全重试，已装的不会重装。
// 文本翻译只依赖两个 set_text；表解密/探针等实验性代码已于 2026-09-04 移除
// （热更新后剧情装载已原生侧化，托管层加解密探针全程零触发，留着只增崩溃面）。
bool install_hooks_by_name() {
    static bool tmp_done = false;    // TextMeshPro 主路径
    static bool ugi_done = false;    // legacy uGUI Text（部分列表/旧UI使用）

    if (!tmp_done)
        tmp_done = hook_text_method("TMPro", "TMP_Text", "set_text",
                                    (void *)my_set_text, (void **)&old_set_text);
    if (!ugi_done)
        ugi_done = hook_text_method("UnityEngine.UI", "Text", "set_text",
                                    (void *)my_ugi_set_text, (void **)&old_ugi_set_text);

    if (ugi_done)
        LOGI("【成功】legacy UI.Text 附加 Hook 生效，覆盖更多文本组件。");

    return tmp_done;
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

            // 全量韩文捕获网：hook 字符串创建 API 的【真实实现】（版本无关）。
            // 任何托管字符串（含原生 AssetBundle 反序列化直接构造的）都要经过
            // 这两个函数，韩文一律入库；失败安全，装不上也不影响翻译。
            // 安全要点：导出符号是 4~8 字节 B 跳板且相邻仅 8 字节，绝不能直接
            // hook 导出地址（16 字节补丁会互相踩踏 → 黑屏卡死）。必须先解析
            // 跳板到真实实现，并校验两个目标间距 ≥ 32 字节、且未被 hook 过。
            {
                size_t sz1 = 0, sz2 = 0;
                void *sym_new = (void *)xdl_sym(handle, "il2cpp_string_new", &sz1);
                void *sym_u16 = (void *)xdl_sym(handle, "il2cpp_string_new_utf16", &sz2);
                uintptr_t il2cpp_base_addr = get_module_base("libil2cpp.so");
                void *t_new = resolve_thunk_target(sym_new, il2cpp_base_addr);
                void *t_u16 = resolve_thunk_target(sym_u16, il2cpp_base_addr);
                LOGI("【韩文库】符号：string_new 导出=%p 目标=%p；utf16 导出=%p 目标=%p",
                     sym_new, t_new, sym_u16, t_u16);

                bool spaced = true;
                if (t_new && t_u16) {
                    uintptr_t d = (uintptr_t)t_new > (uintptr_t)t_u16
                                      ? (uintptr_t)t_new - (uintptr_t)t_u16
                                      : (uintptr_t)t_u16 - (uintptr_t)t_new;
                    if (d < 0x20) {
                        spaced = false;
                        LOGE("【韩文库】两个目标间距仅 %lu 字节（<32），放弃安装以防补丁互踩",
                             (unsigned long)d);
                    }
                }

                if (spaced && t_new && !already_dobby_patched(t_new)) {
                    if (DobbyHook(t_new, (void *)my_string_new, (void **)&old_string_new) == 0) {
                        // 自己造中文替换串时走 trampoline 直抵真实实现，绕过本 hook（防递归/自抓）
                        il2cpp_string_new_ptr = (MyIl2CppString *(*)(const char *))old_string_new;
                        LOGI("【成功】全量韩文库已安装：il2cpp_string_new 真实实现 @ %p", t_new);
                    } else {
                        LOGI("【提示】il2cpp_string_new hook 安装失败，跳过（不影响翻译）");
                    }
                }
                if (spaced && t_u16 && !already_dobby_patched(t_u16)) {
                    if (DobbyHook(t_u16, (void *)my_string_new_utf16,
                                  (void **)&old_string_new_utf16) == 0)
                        LOGI("【成功】全量韩文库已安装：il2cpp_string_new_utf16 真实实现 @ %p", t_u16);
                    else
                        LOGI("【提示】il2cpp_string_new_utf16 hook 安装失败，跳过（不影响翻译）");
                }
                if (!t_new || !t_u16)
                    LOGI("【提示】字符串创建符号未找到，全量韩文库跳过（set_text 捕获仍有效）");
            }

            // 立即安装：self-SIGKILL 已被拦截，游戏启动完整性检测的自杀手段失效，
            // 无需再靠 sleep(25) 躲避检测窗口。文本 hook 越早就位，启动阶段的
            // 韩文捕获与翻译覆盖越完整。
            // hook 安装带重试：启动早期 il2cpp 程序集可能尚未加载完毕
            bool hooked = false;
            for (int retry = 0; retry < 30 && !hooked; retry++) {
                hooked = install_hooks_by_name();
                if (!hooked) {
                    LOGI("【重试】il2cpp 程序集未就绪，第 %d/30 次重试...", retry + 1);
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
