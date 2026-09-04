// Created by Perfare on 2020/7/4.
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
//  11. hook kill/tgkill：拦截针对自身的 SIGKILL（游戏启动完整性检测的自杀手段）
//  12. hook 改为立即安装（不再 sleep 25）：自杀被拦截后无需躲避检测窗口，
//      启动阶段的表解密（kr.client/scenariotextkr.client）才能被抓到
//  13. 修复输入密文 dump 时机：mdq/ewdv 为原地解密（a==b 缓冲），必须在
//      old_* 调用前 dump 密文，调用后 dump 明文，否则密文被明文覆盖
//  14. 新增表加载路径追踪探针（实验性）：
//      - res 全部 Stream 读取入口（mdq/ewdp/ewdv/ewec/cgn/ful/ewds/ewdw/duq/ewdx/ewdo）
//        首次调用打印调用栈 —— 判定 .client 表是否经过 res
//      - MessagePack.LZ4.LZ4Codec.Decode / CLZF2.Decompress —— 抓压缩层输入与输出，
//        若表数据经 LZ4/LZF 解压可直接获得表明文（dump 至 /sdcard/Download/probe_*）
//      - TextAsset.get_bytes/get_text —— ≥64KB 资源 dump 内容并打印调用栈，
//        定位读取 .client TextAsset 的代码链
//      离线分析结论（2026-09-02）：静态 TextAsset 在全部 256 个单字节 XOR key 下
//      均无 mdq 块链 [A][Hash][A-4] 结构，也无 LZ4 magic —— 表解密器另有其人，
//      需要本组探针的运行时证据来定位
//  15. 新增 eti 类 AES 路径 hook（2026-09-04 反汇编结论）：
//      eti.cntp(SymAlg, String password, out key, out iv) 是全部密码路径汇聚点，
//      算法 = Rijndael(=AES) CFB8 + NoPadding，
//      派生 = key/B64(SHA256(pw))[0:32], iv = 拼接串[32:48]（76B = 44B Base64 + 32B hash）
//      hook cntp 直接 dump 密码字符串 + key/IV（/sdcard/Download/eti_key/）
//      eti.cntj/rw/cbb/kis 是解密流工厂（File.OpenRead → 160B 头 → CryptoStream），
//      dump 返回的 MemoryStream 内容（[160B头][解密数据]）即为解密后的表数据
//      （/sdcard/Download/eti_stream/）—— 即使没有密码也能直接拿到表明文

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

bool install_crypto_dumps();      // 前向声明：定义在下方解密 Dump 部分
bool install_table_path_probes(); // 前向声明：定义在下方表加载路径追踪探针部分
static Il2CppClass *find_class_in_assemblies(const char *ns, const char *name); // 前向声明：类查找（含枚举回退）

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
    static bool probe_done = false;  // 表加载路径追踪探针

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

    // 探针随重试循环补装；框架层 hook（mscorlib 版本无关）就绪即视为解密路径就位
    if (!probe_done)
        probe_done = install_table_path_probes();

    // 完成条件：UI 文本 hook + 解密路径 hook。解密路径二选一即可：
    //   crypto_done = 旧版 res XOR dump（依赖混淆类 res，热更新后已失效）
    //   probe_done  = 框架层加解密 hook（SymmetricAlgorithm/CryptoStream/MemoryStream）
    // 热更新后 res/eti 混淆类已改名，框架 hook 为当前版本实际主路径。
    return tmp_done && (crypto_done || probe_done);
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

static const char *kDumpDir = "/sdcard/Download/ewel_dumps";   // 解密输出（明文）
static const char *kInDir   = "/sdcard/Download/ewel_in";      // 解密输入（密文，用于还原文件层变换）
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

// 解密调用后同时 dump 输出明文（a_ptr/a_len）与输入密文（b_ptr/b_len）：
//   - 输出 -> ewel_dumps: 表明文样本
//   - 输入 -> ewel_in:    与文件字节差分，还原文件层加密（密钥流 = 输入 XOR 文件区域）
static void dump_decrypted(const char *func_name, void *a_ptr, int32_t a_len,
                           void *b_ptr, int32_t b_len, NativeDecryptContext *ctx) {
    std::lock_guard<std::mutex> lk(dump_mutex);
    if (dump_count >= kDumpMaxFiles) return;

    unsigned key = ctx ? (uint32_t)ctx->Key : 0;
    int idx = ctx ? ctx->Index : 0;

    // ---- 输出（明文）----
    if (a_ptr != nullptr && a_len >= 16) {
        uint64_t h = fnv1a_hash(a_ptr, (size_t)a_len);
        if (!dumped_hashes.count(h)) {
            char path[256];
            snprintf(path, sizeof(path), "%s/%s_key%08X_len%d_%016llX.bin",
                     kDumpDir, func_name, key, a_len, (unsigned long long)h);
            // 跨重启去重：上次运行已 dump 过同一块则跳过
            if (FILE *test = fopen(path, "rb")) { fclose(test); dumped_hashes.insert(h); }
            else {
                mkdir(kDumpDir, 0777);
                FILE *f = fopen(path, "wb");
                if (f) {
                    fwrite(a_ptr, 1, (size_t)a_len, f);
                    fclose(f);
                    dumped_hashes.insert(h);
                    dump_count++;
                    if (dump_count <= 20 || dump_count % 200 == 0)
                        LOGI("【解密Dump】#%d %s out len=%d key=0x%08X", dump_count, func_name, a_len, key);
                }
            }
        }
    }

    // ---- 输入（密文）----
    if (b_ptr != nullptr && b_len >= 4) {
        uint64_t h = fnv1a_hash(b_ptr, (size_t)b_len);
        if (!dumped_hashes.count(h ^ 0x494E505554ULL)) {  // 与输出哈希空间隔离
            char path[256];
            snprintf(path, sizeof(path), "%s/in_%s_key%08X_idx%d_len%d_%016llX.bin",
                     kInDir, func_name, key, idx, b_len, (unsigned long long)h);
            if (FILE *test = fopen(path, "rb")) { fclose(test); dumped_hashes.insert(h ^ 0x494E505554ULL); }
            else {
                mkdir(kInDir, 0777);
                FILE *f = fopen(path, "wb");
                if (f) {
                    fwrite(b_ptr, 1, (size_t)b_len, f);
                    fclose(f);
                    dumped_hashes.insert(h ^ 0x494E505554ULL);
                    dump_count++;
                    if (dump_count <= 20 || dump_count % 200 == 0)
                        LOGI("【解密Dump】#%d %s in len=%d key=0x%08X idx=%d", dump_count, func_name, b_len, key, idx);
                }
            }
        }
    }
}

// 原语 hook：mdq/ewdv 使用原地解密（a 缓冲 == b 缓冲），old_* 执行后密文即被
// 明文覆盖 —— 因此输入密文必须在调用前 dump，输出明文在调用后 dump。
void my_nrf(void *a_ptr, int32_t a_len, void *b_ptr, int32_t b_len, void *ctx) {
    dump_decrypted("nrf", nullptr, 0, b_ptr, b_len, (NativeDecryptContext *)ctx);
    old_nrf(a_ptr, a_len, b_ptr, b_len, ctx);
    dump_decrypted("nrf", a_ptr, a_len, nullptr, 0, (NativeDecryptContext *)ctx);
}

void my_ewel(void *a_ptr, int32_t a_len, void *b_ptr, int32_t b_len, void *ctx) {
    dump_decrypted("ewel", nullptr, 0, b_ptr, b_len, (NativeDecryptContext *)ctx);
    old_ewel(a_ptr, a_len, b_ptr, b_len, ctx);
    dump_decrypted("ewel", a_ptr, a_len, nullptr, 0, (NativeDecryptContext *)ctx);
}

void my_lqg(void *a_ptr, int32_t a_len, void *b_ptr, int32_t b_len, void *ctx) {
    dump_decrypted("lqg", nullptr, 0, b_ptr, b_len, (NativeDecryptContext *)ctx);
    old_lqg(a_ptr, a_len, b_ptr, b_len, ctx);
    dump_decrypted("lqg", a_ptr, a_len, nullptr, 0, (NativeDecryptContext *)ctx);
}

// 按名查找 res 类的三个解密原语并 hook（逐原语幂等：部分成功后重试只补装缺失的）
bool install_crypto_dumps() {
    static bool nrf_done = false, ewel_done = false, lqg_done = false;
    if (nrf_done && ewel_done && lqg_done) return true;

    // res 类：全局命名空间，位于 Trickcal.AllShared.dll。
    // 注意：本游戏 il2cpp_class_from_name 对空命名空间的混淆类失效，必须走
    // find_class_in_assemblies（内部含 image 类型枚举回退），否则 res 永远找不到。
    Il2CppClass *klass = find_class_in_assemblies("", "res");
    if (klass) {
        LOGI("【解密Dump】找到 res 类，klass=%p", klass);
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

// ==================== 表加载路径追踪探针（实验性）====================
// 背景：离线分析已确认 .client 表不走 res 的 mdq/ewel 路径（运行时 dump 无表级
// 数据，静态 TextAsset 也无对应块结构）。本组探针采集运行时证据定位真正的表解密器。

// IL2CPP 数组布局（64位）：klass@0x00 monitor@0x08 bounds@0x10 length@0x18 data@0x20
// （bounds 在前，length 在后 —— 写反会把 bounds 指针当长度，全部 dump 静默失效）
// 托管指针粗检：IL2CPP/GC 堆对象 16 字节对齐、位于高地址用户空间。
// 防止 hook 到非预期对象（如返回值不是 MemoryStream）时解引用野指针崩溃。
static bool looks_like_managed_ptr(const void *p) {
    uintptr_t a = (uintptr_t)p;
    return a >= 0x10000 && a < 0x80000000000ULL && (a & 0xF) == 0;
}

static uint8_t *probe_array_data(void *arr, int32_t *out_len) {
    if (!arr || !looks_like_managed_ptr(arr)) return nullptr;
    void *bounds = *(void **)((uintptr_t)arr + 0x10);
    int32_t len = *(int32_t *)((uintptr_t)arr + 0x18);
    if (bounds != nullptr) return nullptr;  // 多维数组不处理
    if (len <= 0 || len > (64 << 20)) return nullptr;
    *out_len = len;
    return (uint8_t *)((uintptr_t)arr + 0x20);
}

static int32_t probe_string_length(void *s) {
    if (!s || !looks_like_managed_ptr(s)) return 0;
    int32_t n = *(int32_t *)((uintptr_t)s + 0x10);
    return (n >= 0 && n < 1024 * 1024) ? n : 0;  // 合理字符串长度上限 1MB
}

// 带标签的调用栈打印（RVA 相对 libil2cpp.so 基址）
static void print_callstack_tagged(const char *tag, int max_frames = 24) {
    uintptr_t base = get_module_base("libil2cpp.so");
    void **fp = (void **)__builtin_frame_address(0);
    LOGI("【调用栈:%s】==================", tag);
    for (int i = 0; i < max_frames && fp != nullptr; i++) {
        uintptr_t ra = (uintptr_t)(*(fp + 1));
        if (ra > base && base != 0)
            LOGI("【%s#%02d】RVA 0x%lx", tag, i, (unsigned long)(ra - base));
        void **next = (void **)(*fp);
        if (next <= fp) break;
        fp = next;
    }
    LOGI("【调用栈:%s】==================", tag);
}

// 探针 blob dump（按 tag 分目录，内容哈希去重，跨重启跳过已存在文件）
static std::unordered_set<uint64_t> probe_dumped;
static int probe_dump_count = 0;

static void dump_probe_blob(const char *tag, const void *data, size_t len) {
    if (data == nullptr || len < 16) return;
    std::lock_guard<std::mutex> lk(dump_mutex);
    if (probe_dump_count >= kDumpMaxFiles) return;
    uint64_t h = fnv1a_hash(data, len);
    if (!probe_dumped.insert(h).second) return;
    char dir[256];
    snprintf(dir, sizeof(dir), "/sdcard/Download/probe_%s", tag);
    mkdir("/sdcard/Download", 0777);
    mkdir(dir, 0777);
    char path[512];
    snprintf(path, sizeof(path), "%s/%s_len%zu_%016llX.bin", dir, tag, len,
             (unsigned long long)h);
    if (FILE *test = fopen(path, "rb")) { fclose(test); return; }  // 上轮已 dump
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(data, 1, len, f);
        fclose(f);
        probe_dump_count++;
        if (probe_dump_count <= 20 || probe_dump_count % 100 == 0)
            LOGI("【探针Dump】%s #%d len=%zu", tag, probe_dump_count, len);
    }
}

// ---- 1) res Stream 读取入口追踪 ----

static void *(*old_mdq)(void *, void *) = nullptr;    // reu mdq(Stream)
static void *(*old_ewdp)(void *, void *) = nullptr;   // reu ewdp(Stream)
static void *(*old_ewdv)(void *, void *) = nullptr;   // reu ewdv(Stream)
static void *(*old_ewec)(void *, void *) = nullptr;   // String ewec(Stream)
static void *(*old_cgn)(void *, void *) = nullptr;    // qea cgn(Stream)
static bool (*old_ful)(void *, void *) = nullptr;     // Boolean ful(Stream)
static bool (*old_ewds)(void *, void *) = nullptr;    // Boolean ewds(Stream)
static bool (*old_ewdw)(void *, void *) = nullptr;    // Boolean ewdw(Stream)
static int (*old_duq)(void *, void *) = nullptr;      // Int32 duq(Stream)
static int (*old_ewdx)(void *, void *) = nullptr;     // Int32 ewdx(Stream)
static int (*old_ewdo)(void *, void *) = nullptr;     // Int32 ewdo(Stream)

static void trace_res_entry(const char *name) {
    static std::unordered_map<std::string, int> counts;
    static bool first_callstack_done = false;
    std::lock_guard<std::mutex> lk(dump_mutex);
    int c = ++counts[name];
    if (c <= 3 || c % 500 == 0)
        LOGI("【res入口】%s 第%d次调用", name, c);
    if (!first_callstack_done) {
        first_callstack_done = true;
        print_callstack_tagged("res入口");
    }
}

static void *my_mdq(void *self, void *stream)  { trace_res_entry("mdq");  return old_mdq(self, stream); }
static void *my_ewdp(void *self, void *stream) { trace_res_entry("ewdp"); return old_ewdp(self, stream); }
static void *my_ewdv(void *self, void *stream) { trace_res_entry("ewdv"); return old_ewdv(self, stream); }
static void *my_ewec(void *self, void *stream) { trace_res_entry("ewec"); return old_ewec(self, stream); }
static void *my_cgn(void *self, void *stream)  { trace_res_entry("cgn");  return old_cgn(self, stream); }
static bool my_ful(void *self, void *stream)   { trace_res_entry("ful");  return old_ful(self, stream); }
static bool my_ewds(void *self, void *stream)  { trace_res_entry("ewds"); return old_ewds(self, stream); }
static bool my_ewdw(void *self, void *stream)  { trace_res_entry("ewdw"); return old_ewdw(self, stream); }
static int my_duq(void *self, void *stream)    { trace_res_entry("duq");  return old_duq(self, stream); }
static int my_ewdx(void *self, void *stream)   { trace_res_entry("ewdx"); return old_ewdx(self, stream); }
static int my_ewdo(void *self, void *stream)   { trace_res_entry("ewdo"); return old_ewdo(self, stream); }

// ---- 2) 压缩层探针：MessagePack.LZ4.LZ4Codec.Decode / CLZF2.Decompress ----

// static Int32 Decode(Byte[] input, Int32 inputOffset, Int32 inputLength,
//                     Byte[] output, Int32 outputOffset, Int32 outputLength)
static int (*old_mp_lz4_decode)(void *, int32_t, int32_t, void *, int32_t, int32_t) = nullptr;

static int my_mp_lz4_decode(void *input, int32_t inOff, int32_t inLen,
                            void *output, int32_t outOff, int32_t outLen) {
    int r = old_mp_lz4_decode(input, inOff, inLen, output, outOff, outLen);
    // 输出 = 解压后的 MsgPack 明文（表/嵌套块），输入 = 压缩块
    int32_t olen = 0, ilen = 0;
    uint8_t *odata = probe_array_data(output, &olen);
    if (odata != nullptr && r > 0 && outOff >= 0 && (int64_t)outOff + r <= olen)
        dump_probe_blob("lz4out", odata + outOff, (size_t)r);
    uint8_t *idata = probe_array_data(input, &ilen);
    if (idata != nullptr && inLen > 0 && inOff >= 0 && (int64_t)inOff + inLen <= ilen)
        dump_probe_blob("lz4in", idata + inOff, (size_t)inLen);
    return r;
}

// static Byte[] Decompress(Byte[] inputBytes)
static void *(*old_clzf2_dec)(void *) = nullptr;

static void *my_clzf2_dec(void *input) {
    void *r = old_clzf2_dec(input);
    int32_t ilen = 0, rlen = 0;
    uint8_t *idata = probe_array_data(input, &ilen);
    if (idata != nullptr) dump_probe_blob("lzfsrc", idata, (size_t)ilen);
    uint8_t *rdata = probe_array_data(r, &rlen);
    if (rdata != nullptr) dump_probe_blob("lzfout", rdata, (size_t)rlen);
    return r;
}

// ---- 3) TextAsset 探针：get_bytes / get_text ----

static void *(*old_ta_bytes)(void *) = nullptr;
static void *(*old_ta_text)(void *) = nullptr;

static void *my_ta_bytes(void *self) {
    void *r = old_ta_bytes(self);
    int32_t len = 0;
    uint8_t *d = probe_array_data(r, &len);
    if (d != nullptr && len >= 65536) {
        dump_probe_blob("textasset", d, (size_t)len);
        static bool cs_done = false;
        if (!cs_done) {
            cs_done = true;
            print_callstack_tagged("TextAsset.bytes");
        }
    }
    return r;
}

static void *my_ta_text(void *self) {
    void *r = old_ta_text(self);
    int32_t len = probe_string_length(r);
    if (len >= 65536) {
        dump_probe_blob("textasset_str", (const void *)((uintptr_t)r + 0x14),
                        (size_t)len * 2);  // UTF-16
        static bool cs_done = false;
        if (!cs_done) {
            cs_done = true;
            print_callstack_tagged("TextAsset.text");
        }
    }
    return r;
}

// ---- 5) eti 类 AES 解密路径 hook（2026-09-04 反汇编定位）----
// eti.cntp(SymmetricAlgorithm a, String b, out Byte[] c, out Byte[] d)
//   密钥派生：combined = ASCII(Base64(SHA256(UTF8(pw)))) ++ SHA256(pw)（76B）
//             key = combined[0:KeySize/8]（默认 32B）, iv = combined[32:32+BlockSize/8]（默认 16B）
//   算法由 cnto/bbm 配置：Mode=CFB(4), FeedbackSize=8, Padding=None(1)
static void (*old_eti_cntp)(void *alg, void *pw, void **out_key, void **out_iv) = nullptr;

static std::string eti_to_hex(const uint8_t *d, int n) {
    static const char *hx = "0123456789ABCDEF";
    std::string s;
    for (int i = 0; i < n; i++) { s += hx[d[i] >> 4]; s += hx[d[i] & 15]; }
    return s;
}

static void my_eti_cntp(void *alg, void *pw, void **out_key, void **out_iv) {
    old_eti_cntp(alg, pw, out_key, out_iv);
    // 密码字符串（IL2CPP string: length@0x10, UTF-16 chars@0x14）
    if (pw != nullptr) {
        int32_t plen = probe_string_length(pw);
        if (plen > 0 && plen < 1024) {
            static std::unordered_set<std::string> logged_pw;
            std::string s = utf16_to_utf8((const char16_t *)((uintptr_t)pw + 0x14), plen);
            dump_probe_blob("eti_pw", s.c_str(), s.size());
            if (logged_pw.insert(s).second) {
                LOGI("【密钥派生】password=\"%s\" (len=%d)", s.c_str(), plen);
            }
        }
    }
    // 派生结果 key/IV（out 参数指向 IL2CPP byte[] 槽位）
    if (out_key != nullptr && *out_key != nullptr) {
        int32_t klen = 0;
        uint8_t *kd = probe_array_data(*out_key, &klen);
        if (kd != nullptr && klen > 0) {
            dump_probe_blob("eti_key", kd, (size_t)klen);
            static std::string last_key;
            std::string hex = eti_to_hex(kd, klen < 64 ? klen : 64);
            if (hex != last_key) {
                last_key = hex;
                LOGI("【密钥派生】key len=%d hex=%s", klen, hex.c_str());
            }
        }
    }
    if (out_iv != nullptr && *out_iv != nullptr) {
        int32_t ilen = 0;
        uint8_t *id = probe_array_data(*out_iv, &ilen);
        if (id != nullptr && ilen > 0) {
            dump_probe_blob("eti_iv", id, (size_t)ilen);
            static std::string last_iv;
            std::string hex = eti_to_hex(id, ilen < 64 ? ilen : 64);
            if (hex != last_iv) {
                last_iv = hex;
                LOGI("【密钥派生】iv len=%d hex=%s", ilen, hex.c_str());
            }
        }
    }
}

// eti.cntj/rw/cbb/kis(String) → Stream 解密流工厂
// eti.cnti(String a, String b, String c) = Path.Combine 包装，最终仍然走解密流（dump.cs 已验证）
//   File.OpenRead(path) → 读 hlys=160B 头写入 MemoryStream → CryptoStream(其余, 解密器)
//   → CopyTo 同一 MemoryStream → 返回。返回对象首字段(@0x10) = _buffer byte[]，
//   内容 = [160B 头][AES 解密后的表数据]
static void *(*old_eti_cnti)(void *a, void *b, void *c) = nullptr;
static void *(*old_eti_cntj)(void *path) = nullptr;
static void *(*old_eti_rw)(void *path) = nullptr;
static void *(*old_eti_cbb)(void *path) = nullptr;
static void *(*old_eti_kis)(void *path) = nullptr;

static void eti_log_path(const char *factory, void *path) {
    if (path == nullptr) return;
    int32_t plen = probe_string_length(path);
    if (plen <= 0 || plen >= 1024) return;
    std::string p = utf16_to_utf8((const char16_t *)((uintptr_t)path + 0x14), plen);
    static std::unordered_set<std::string> logged_paths;
    if (logged_paths.insert(p).second) {
        LOGI("【eti解密流】%s path=\"%s\"", factory, p.c_str());
    }
}

static std::string eti_get_string(void *s) {
    if (s == nullptr) return {};
    int32_t n = probe_string_length(s);
    if (n <= 0 || n >= 1024) return {};
    return utf16_to_utf8((const char16_t *)((uintptr_t)s + 0x14), n);
}

static void eti_dump_result_stream(void *result) {
    if (!looks_like_managed_ptr(result)) return;
    void *buf = *(void **)((uintptr_t)result + 0x10);  // MemoryStream._buffer
    if (!looks_like_managed_ptr(buf)) {
        LOGI("【eti解密流】返回对象 _buffer 指针异常 %p（可能非 MemoryStream，跳过 dump）", buf);
        return;
    }
    int32_t blen = 0;
    uint8_t *bd = probe_array_data(buf, &blen);
    if (bd != nullptr) dump_probe_blob("eti_stream", bd, (size_t)blen);
}

static void *my_eti_cnti(void *a, void *b, void *c) {
    std::string A = eti_get_string(a), B = eti_get_string(b), C = eti_get_string(c);
    if (!A.empty() || !B.empty() || !C.empty()) {
        static std::unordered_map<std::string, bool> seen;
        std::string key = A + "|" + B + "|" + C;
        if (seen.find(key) == seen.end()) {
            seen[key] = true;
            LOGI("【eti解密流】cnti combine(\"%s\", \"%s\", \"%s\")", A.c_str(), B.c_str(), C.c_str());
        }
    }
    void *r = old_eti_cnti(a, b, c);
    eti_dump_result_stream(r);
    return r;
}
static void *my_eti_cntj(void *path) { eti_log_path("cntj", path); void *r = old_eti_cntj(path); eti_dump_result_stream(r); return r; }
static void *my_eti_rw(void *path)   { eti_log_path("rw", path);   void *r = old_eti_rw(path);   eti_dump_result_stream(r); return r; }
static void *my_eti_cbb(void *path)  { eti_log_path("cbb", path);  void *r = old_eti_cbb(path);  eti_dump_result_stream(r); return r; }
static void *my_eti_kis(void *path)  { eti_log_path("kis", path);  void *r = old_eti_kis(path);  eti_dump_result_stream(r); return r; }

// ---- 框架层加解密 hook（版本无关兜底，2026-09-04 新增）----
// 游戏热更新后 Assembly-CSharp 混淆类名全部重排（实测：枚举 169 个 image 约 4 万
// 个类已无 eti/res，运行时 libil2cpp 符号地址与旧版固定偏移 0x331D0）。
// 但 AES 解密最终必经 mscorlib 框架类，类名永远稳定：
//   - SymmetricAlgorithm.set_Key / set_IV：直接抓 AES 密钥与 IV（RijndaelManaged
//     不重写这两个 setter，hook 基类即可全部命中）
//   - CryptoStream.ctor / Read：Read 返回的 buffer 即【解密后明文分块】
//   - MemoryStream.ToArray：解密结果 CopyTo 到 MemoryStream 后，游戏取整表时
//     大概率调用 ToArray()，可一次性拿到【整张表明文】（≥16KB 才落盘）
static void (*old_sys_set_key)(void *, void *) = nullptr;
static void (*old_sys_set_iv)(void *, void *) = nullptr;
static int  (*old_sys_cs_read)(void *, void *, int32_t, int32_t) = nullptr;
static void (*old_sys_cs_ctor)(void *, void *, void *, int32_t) = nullptr;
static void *(*old_sys_ms_toarray)(void *) = nullptr;

static void my_sys_set_key(void *thiz, void *arr) {
    old_sys_set_key(thiz, arr);
    int32_t n = 0;
    uint8_t *d = probe_array_data(arr, &n);
    if (d && n > 0) {
        dump_probe_blob("sys_key", d, (size_t)n);
        static std::string last;
        std::string hx = eti_to_hex(d, n < 64 ? n : 64);
        if (hx != last) { last = hx; LOGI("【系统加密】SymmetricAlgorithm.set_Key len=%d hex=%s", n, hx.c_str()); }
    }
}

static void my_sys_set_iv(void *thiz, void *arr) {
    old_sys_set_iv(thiz, arr);
    int32_t n = 0;
    uint8_t *d = probe_array_data(arr, &n);
    if (d && n > 0) {
        dump_probe_blob("sys_iv", d, (size_t)n);
        static std::string last;
        std::string hx = eti_to_hex(d, n < 64 ? n : 64);
        if (hx != last) { last = hx; LOGI("【系统加密】SymmetricAlgorithm.set_IV len=%d hex=%s", n, hx.c_str()); }
    }
}

// public override Int32 Read(Byte[] buffer, Int32 offset, Int32 count)
static int my_sys_cs_read(void *thiz, void *buf, int32_t off, int32_t count) {
    int r = old_sys_cs_read(thiz, buf, off, count);
    if (r > 0) {
        int32_t blen = 0;
        uint8_t *bd = probe_array_data(buf, &blen);
        if (bd && off >= 0 && (int64_t)off + r <= blen)
            dump_probe_blob("sys_plain", bd + off, (size_t)r);  // 解密后明文分块
    }
    return r;
}

// .ctor(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
static void my_sys_cs_ctor(void *thiz, void *stream, void *xform, int32_t mode) {
    old_sys_cs_ctor(thiz, stream, xform, mode);
    static int n = 0;
    if (++n <= 20)
        LOGI("【系统解密流】CryptoStream.ctor #%d mode=%d(0=读/解密 1=写/加密) stream=%p xform=%p",
             n, mode, stream, xform);
}

// public virtual Byte[] ToArray()
static void *my_sys_ms_toarray(void *thiz) {
    void *arr = old_sys_ms_toarray(thiz);
    int32_t n = 0;
    uint8_t *d = probe_array_data(arr, &n);
    if (d && n >= 16384) {  // 只抓大块：解密后的整张表；UI/临时小对象跳过
        dump_probe_blob("sys_table", d, (size_t)n);
        static int cnt = 0;
        if (++cnt <= 30) LOGI("【系统解密流】MemoryStream.ToArray len=%d（疑似整表明文）", n);
    }
    return arr;
}

// 双保险：RijndaelManaged 重写了 CreateDecryptor(Byte[], Byte[]) / CreateEncryptor，
// 游戏若直接用 2 参工厂（不先给 Key/IV 属性赋值），set_Key/set_IV 不会触发；
// 这里直接从工厂参数抓 key/iv。本 hook 为附加项，查找失败不影响主流程。
static void *(*old_sys_create_dec)(void *, void *, void *) = nullptr;
static void *(*old_sys_create_enc)(void *, void *, void *) = nullptr;

static void sys_dump_key_iv(const char *via, void *key, void *iv) {
    int32_t kn = 0, ivn = 0;
    uint8_t *kd = probe_array_data(key, &kn);
    uint8_t *id = probe_array_data(iv, &ivn);
    if (kd && kn > 0) {
        dump_probe_blob("sys_key", kd, (size_t)kn);
        static std::string last_k;
        std::string hx = eti_to_hex(kd, kn < 64 ? kn : 64);
        if (hx != last_k) { last_k = hx; LOGI("【系统加密】%s key len=%d hex=%s", via, kn, hx.c_str()); }
    }
    if (id && ivn > 0) {
        dump_probe_blob("sys_iv", id, (size_t)ivn);
        static std::string last_i;
        std::string hx = eti_to_hex(id, ivn < 64 ? ivn : 64);
        if (hx != last_i) { last_i = hx; LOGI("【系统加密】%s iv len=%d hex=%s", via, ivn, hx.c_str()); }
    }
}

// public override ICryptoTransform CreateDecryptor(Byte[] rgbKey, Byte[] rgbIV)
static void *my_sys_create_dec(void *thiz, void *key, void *iv) {
    void *r = old_sys_create_dec(thiz, key, iv);
    sys_dump_key_iv("RijndaelManaged.CreateDecryptor", key, iv);
    return r;
}

// public override ICryptoTransform CreateEncryptor(Byte[] rgbKey, Byte[] rgbIV)
static void *my_sys_create_enc(void *thiz, void *key, void *iv) {
    void *r = old_sys_create_enc(thiz, key, iv);
    sys_dump_key_iv("RijndaelManaged.CreateEncryptor", key, iv);
    return r;
}

// ---- 按名查找并安装全部探针（幂等，可随重试循环补装）----

// ---- 类查找：il2cpp_class_from_name 对混淆类失效 + 枚举回退 ----
// 实测（2026-09-04，libil2cpp.so 反汇编证实）：本游戏 il2cpp_class_from_name
// 内部在 image+0x30 懒建名称表，查找成功后还要做一轮字符串指针比较校验；
// 对命名空间为空的混淆类（res/eti）始终返回 null（带命名空间的正常名类
// 如 CLZF2/TextAsset 不受影响）。回退方案：用 il2cpp_image_get_class 按
// 类型定义索引枚举 image 内全部类（Zygisk-Il2CppDumper 同款路径），
// 直接对 klass->name / klass->namespaze 做 strcmp 内容比较。
typedef size_t (*fn_image_get_class_count)(const void *image);
typedef void *(*fn_image_get_class)(const void *image, size_t index);
typedef const char *(*fn_class_get_name)(void *klass);
typedef const char *(*fn_class_get_namespace)(void *klass);

static fn_image_get_class_count  p_image_get_class_count = nullptr;
static fn_image_get_class        p_image_get_class       = nullptr;
static fn_class_get_name         p_class_get_name        = nullptr;
static fn_class_get_namespace    p_class_get_namespace   = nullptr;

static void enum_lookup_apis_init() {
    static bool tried = false;
    if (tried) return;
    tried = true;
    void *h = xdl_open("libil2cpp.so", 0);
    if (!h) { LOGE("【类查找】枚举回退初始化失败：libil2cpp.so 打开失败"); return; }
    size_t sz = 0;
    p_image_get_class_count = (fn_image_get_class_count)xdl_sym(h, "il2cpp_image_get_class_count", &sz);
    p_image_get_class       = (fn_image_get_class)xdl_sym(h, "il2cpp_image_get_class", &sz);
    p_class_get_name        = (fn_class_get_name)xdl_sym(h, "il2cpp_class_get_name", &sz);
    p_class_get_namespace   = (fn_class_get_namespace)xdl_sym(h, "il2cpp_class_get_namespace", &sz);
    if (p_image_get_class_count && p_image_get_class && p_class_get_name)
        LOGI("【类查找】枚举回退 API 就绪（image_get_class=%p, class_get_name=%p, ns=%p）",
             p_image_get_class, p_class_get_name, p_class_get_namespace);
    else
        LOGE("【类查找】枚举回退 API 解析失败（%p %p %p %p）",
             p_image_get_class_count, p_image_get_class, p_class_get_name, p_class_get_namespace);
}

static bool ns_is_empty(const char *s) { return s == nullptr || s[0] == '\0'; }

// 类查找负缓存：全库枚举（169 image 约 4 万类）单次约 0.3s，重试循环里对
// 已确认不存在的名字（热更新后改名的 res/eti）反复枚举纯属浪费。
// 负缓存只作用于【枚举回退】路径；标准 class_from_name 快速路径每次仍执行，
// 后加载程序集中新出现的类（走快速路径即可命中的框架/带命名空间类）不受影响。
static std::unordered_set<std::string> g_class_lookup_negative;

static Il2CppClass *find_class_in_assemblies(const char *ns, const char *name) {
    auto domain = il2cpp_domain_get();
    if (!domain) return nullptr;
    size_t assembly_count = 0;
    const Il2CppAssembly **assemblies = il2cpp_domain_get_assemblies(domain, &assembly_count);
    if (!assemblies || assembly_count == 0) return nullptr;

    // 1) 快速路径：标准按名查找（带命名空间的类走这里即可命中）
    for (size_t i = 0; i < assembly_count; i++) {
        const Il2CppImage *image = il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;
        Il2CppClass *klass = il2cpp_class_from_name(image, ns, name);
        if (klass) return klass;
    }

    // 2) 回退路径：逐 image 枚举全部类型定义，直接比较 name/namespace 内容
    enum_lookup_apis_init();
    if (!p_image_get_class_count || !p_image_get_class || !p_class_get_name) return nullptr;

    // 负缓存：此前已全库枚举确认不存在的名字，跳过昂贵枚举
    std::string neg_key = std::string(ns ? ns : "") + "|" + name;
    if (g_class_lookup_negative.count(neg_key)) return nullptr;

    static bool logged_scan = false;
    Il2CppClass *name_only_match = nullptr;
    size_t name_only_count = 0;
    const char *name_only_ns = nullptr;

    for (size_t i = 0; i < assembly_count; i++) {
        const Il2CppImage *image = il2cpp_assembly_get_image(assemblies[i]);
        if (!image) continue;
        size_t cnt = p_image_get_class_count((const void *)image);
        if (!logged_scan)
            LOGI("【类查找】枚举 image[%zu] 类型数=%zu（目标 %s.%s）",
                 i, cnt, (ns && ns[0]) ? ns : "<global>", name);
        for (size_t j = 0; j < cnt; j++) {
            Il2CppClass *klass = (Il2CppClass *)p_image_get_class((const void *)image, j);
            if (!klass) continue;
            const char *kn = p_class_get_name((void *)klass);
            if (!kn || strcmp(kn, name) != 0) continue;
            const char *kns = p_class_get_namespace ? p_class_get_namespace((void *)klass) : nullptr;
            bool ns_ok = (ns && ns[0]) ? (kns && strcmp(kns, ns) == 0) : ns_is_empty(kns);
            if (ns_ok) {
                LOGI("【类查找】%s 通过枚举命中（class_from_name 对该类失效；namespace=\"%s\" image[%zu] idx=%zu）",
                     name, kns ? kns : "", i, j);
                return klass;
            }
            // 名字命中但命名空间不符：记录候选（应对命名空间被混淆成特殊字节的情况）
            name_only_count++;
            if (!name_only_match) { name_only_match = klass; name_only_ns = kns; }
        }
    }
    logged_scan = true;

    // 目标在全局命名空间时，若全部 image 中仅有 1 个同名类，即使命名空间字段
    // 异常（非空/被混淆）也采用，但打出醒目告警便于日志复核
    if ((!ns || !ns[0]) && name_only_count == 1 && name_only_match) {
        LOGI("【类查找】%s 命名空间字段异常但全库唯一同名，采用之（namespace=\"%s\"）",
             name, name_only_ns ? name_only_ns : "(null)");
        return name_only_match;
    }
    if (name_only_count > 1)
        LOGE("【类查找】%s 存在 %zu 个同名类但命名空间均不匹配，放弃", name, name_only_count);
    g_class_lookup_negative.insert(neg_key);  // 全库枚举未命中：负缓存，后续重试直接跳过
    return nullptr;
}

bool install_table_path_probes() {
    static bool res_done = false, mp_done = false, clzf_done = false, ta_done = false,
                eti_done = false, sys_done = false;
    // 框架层 hook（mscorlib，类名永不混淆）是版本无关主路径，就绪即视为完成；
    // res/eti 为旧版混淆类名，热更新后已不存在，不再作为完成条件
    if (sys_done) return true;

    // 1) res 入口（全局命名空间，Trickcal.AllShared）
    if (!res_done) {
        Il2CppClass *klass = find_class_in_assemblies("", "res");
        if (klass) {
            struct Entry { const char *name; void *replace; void **origin; bool ok; };
            static Entry entries[] = {
                {"mdq",  (void *)my_mdq,  (void **)&old_mdq,  false},
                {"ewdp", (void *)my_ewdp, (void **)&old_ewdp, false},
                {"ewdv", (void *)my_ewdv, (void **)&old_ewdv, false},
                {"ewec", (void *)my_ewec, (void **)&old_ewec, false},
                {"cgn",  (void *)my_cgn,  (void **)&old_cgn,  false},
                {"ful",  (void *)my_ful,  (void **)&old_ful,  false},
                {"ewds", (void *)my_ewds, (void **)&old_ewds, false},
                {"ewdw", (void *)my_ewdw, (void **)&old_ewdw, false},
                {"duq",  (void *)my_duq,  (void **)&old_duq,  false},
                {"ewdx", (void *)my_ewdx, (void **)&old_ewdx, false},
                {"ewdo", (void *)my_ewdo, (void **)&old_ewdo, false},
            };
            bool all = true;
            for (auto &e : entries) {
                if (e.ok) continue;
                const MethodInfo *m = il2cpp_class_get_method_from_name(klass, e.name, 1);
                if (m && m->methodPointer) {
                    DobbyHook((void *)m->methodPointer, e.replace, e.origin);
                    e.ok = true;
                    LOGI("【探针】res.%s 入口追踪已安装", e.name);
                } else {
                    all = false;
                }
            }
            res_done = all;
        }
    }

    // 2) MessagePack.LZ4.LZ4Codec.Decode
    if (!mp_done) {
        Il2CppClass *klass = find_class_in_assemblies("MessagePack.LZ4", "LZ4Codec");
        if (klass) {
            const MethodInfo *m = il2cpp_class_get_method_from_name(klass, "Decode", 6);
            if (m && m->methodPointer) {
                DobbyHook((void *)m->methodPointer, (void *)my_mp_lz4_decode,
                          (void **)&old_mp_lz4_decode);
                mp_done = true;
                LOGI("【探针】MessagePack.LZ4.LZ4Codec.Decode 已安装");
            }
        }
    }

    // 3) CLZF2.Decompress（UnityEngine.UI.Extensions）
    if (!clzf_done) {
        Il2CppClass *klass = find_class_in_assemblies("UnityEngine.UI.Extensions", "CLZF2");
        if (klass) {
            const MethodInfo *m = il2cpp_class_get_method_from_name(klass, "Decompress", 1);
            if (m && m->methodPointer) {
                DobbyHook((void *)m->methodPointer, (void *)my_clzf2_dec,
                          (void **)&old_clzf2_dec);
                clzf_done = true;
                LOGI("【探针】CLZF2.Decompress 已安装");
            }
        }
    }

    // 4) TextAsset.get_bytes / get_text
    if (!ta_done) {
        Il2CppClass *klass = find_class_in_assemblies("UnityEngine", "TextAsset");
        if (klass) {
            const MethodInfo *m1 = il2cpp_class_get_method_from_name(klass, "get_bytes", 0);
            if (m1 && m1->methodPointer) {
                DobbyHook((void *)m1->methodPointer, (void *)my_ta_bytes,
                          (void **)&old_ta_bytes);
                LOGI("【探针】TextAsset.get_bytes 已安装");
            } else {
                LOGI("【提示】TextAsset.get_bytes 方法查找失败");
            }
            const MethodInfo *m2 = il2cpp_class_get_method_from_name(klass, "get_text", 0);
            if (m2 && m2->methodPointer) {
                DobbyHook((void *)m2->methodPointer, (void *)my_ta_text,
                          (void **)&old_ta_text);
                LOGI("【探针】TextAsset.get_text 已安装");
            }
            // get_bytes 为主探针；get_text 仅辅助
            ta_done = (m1 && m1->methodPointer);
        }
    }

    // 5) eti 类 AES 解密路径：cntp 密钥派生 + cnti(3参)/cntj/rw/cbb/kis 解密流工厂
    //    - 1 参工厂 cntj/rw/cbb/kis 直接对文件路径解密
    //    - 3 参工厂 cnti = Path.Combine 包装，剧情表加载也会走它（dump.cs 已验证）
    if (!eti_done) {
        Il2CppClass *klass = find_class_in_assemblies("", "eti");
        if (klass) {
            bool cntp_ok = false;
            const MethodInfo *mp = il2cpp_class_get_method_from_name(klass, "cntp", 4);
            if (mp && mp->methodPointer) {
                DobbyHook((void *)mp->methodPointer, (void *)my_eti_cntp,
                          (void **)&old_eti_cntp);
                cntp_ok = true;
                LOGI("【探针】eti.cntp 密钥派生已安装");
            } else {
                LOGI("【提示】eti.cntp 方法查找失败");
            }
            struct EtiEntry { const char *name; int argc; void *replace; void **origin; bool ok; };
            static EtiEntry eti_entries[] = {
                {"cnti", 3, (void *)my_eti_cnti, (void **)&old_eti_cnti, false},
                {"cntj", 1, (void *)my_eti_cntj, (void **)&old_eti_cntj, false},
                {"rw",   1, (void *)my_eti_rw,   (void **)&old_eti_rw,   false},
                {"cbb",  1, (void *)my_eti_cbb,  (void **)&old_eti_cbb,  false},
                {"kis",  1, (void *)my_eti_kis,  (void **)&old_eti_kis,  false},
            };
            bool all = true;
            for (auto &e : eti_entries) {
                if (e.ok) continue;
                const MethodInfo *m = il2cpp_class_get_method_from_name(klass, e.name, e.argc);
                if (m && m->methodPointer) {
                    DobbyHook((void *)m->methodPointer, e.replace, e.origin);
                    e.ok = true;
                    LOGI("【探针】eti.%s 解密流工厂已安装（%d参）", e.name, e.argc);
                } else {
                    all = false;
                    LOGI("【提示】eti.%s(%d) 方法查找失败", e.name, e.argc);
                }
            }
            eti_done = cntp_ok && all;
        } else {
            LOGI("【提示】eti 类查找失败（AES 解密路径 hook 未安装）");
        }
    }

    // 6) 框架层加解密 hook（版本无关主路径，2026-09-04）
    //    游戏热更新后 Assembly-CSharp 混淆类名全部重排（枚举 169 image 约 4 万
    //    类已无 eti/res），但 AES 解密最终必经 mscorlib 框架类，类名永不混淆：
    //    - SymmetricAlgorithm.set_Key/set_IV：抓 AES 密钥/IV。RijndaelManaged
    //      不重写这两个 setter（无参 CreateDecryptor 路径必经属性赋值），
    //      hook 基类即命中全部对称算法实例
    //    - RijndaelManaged.CreateDecryptor/CreateEncryptor(2参)：双保险，
    //      直接从工厂参数抓 key/iv（附加项，查找失败不阻塞）
    //    - CryptoStream..ctor(3参)/Read(3参)：Read 返回 buffer 即解密明文分块
    //    - MemoryStream.ToArray(0参)：解密 CopyTo 后取整表，≥16KB 才落盘
    if (!sys_done) {
        bool sys_ok = true;

        Il2CppClass *sa = find_class_in_assemblies("System.Security.Cryptography",
                                                   "SymmetricAlgorithm");
        if (sa) {
            const MethodInfo *mk = il2cpp_class_get_method_from_name(sa, "set_Key", 1);
            if (mk && mk->methodPointer) {
                DobbyHook((void *)mk->methodPointer, (void *)my_sys_set_key,
                          (void **)&old_sys_set_key);
                LOGI("【探针】SymmetricAlgorithm.set_Key 已安装（地址 %p）", mk->methodPointer);
            } else { sys_ok = false; LOGI("【提示】SymmetricAlgorithm.set_Key 查找失败"); }

            const MethodInfo *miv = il2cpp_class_get_method_from_name(sa, "set_IV", 1);
            if (miv && miv->methodPointer) {
                DobbyHook((void *)miv->methodPointer, (void *)my_sys_set_iv,
                          (void **)&old_sys_set_iv);
                LOGI("【探针】SymmetricAlgorithm.set_IV 已安装（地址 %p）", miv->methodPointer);
            } else { sys_ok = false; LOGI("【提示】SymmetricAlgorithm.set_IV 查找失败"); }
        } else { sys_ok = false; LOGI("【提示】SymmetricAlgorithm 类查找失败"); }

        Il2CppClass *csk = find_class_in_assemblies("System.Security.Cryptography",
                                                    "CryptoStream");
        if (csk) {
            const MethodInfo *mc = il2cpp_class_get_method_from_name(csk, ".ctor", 3);
            if (mc && mc->methodPointer) {
                DobbyHook((void *)mc->methodPointer, (void *)my_sys_cs_ctor,
                          (void **)&old_sys_cs_ctor);
                LOGI("【探针】CryptoStream..ctor(3参) 已安装（地址 %p）", mc->methodPointer);
            } else { sys_ok = false; LOGI("【提示】CryptoStream..ctor(3参) 查找失败"); }

            const MethodInfo *mr = il2cpp_class_get_method_from_name(csk, "Read", 3);
            if (mr && mr->methodPointer) {
                DobbyHook((void *)mr->methodPointer, (void *)my_sys_cs_read,
                          (void **)&old_sys_cs_read);
                LOGI("【探针】CryptoStream.Read(3参) 已安装（地址 %p）", mr->methodPointer);
            } else { sys_ok = false; LOGI("【提示】CryptoStream.Read(3参) 查找失败"); }
        } else { sys_ok = false; LOGI("【提示】CryptoStream 类查找失败"); }

        Il2CppClass *ms = find_class_in_assemblies("System.IO", "MemoryStream");
        if (ms) {
            const MethodInfo *mt = il2cpp_class_get_method_from_name(ms, "ToArray", 0);
            if (mt && mt->methodPointer) {
                DobbyHook((void *)mt->methodPointer, (void *)my_sys_ms_toarray,
                          (void **)&old_sys_ms_toarray);
                LOGI("【探针】MemoryStream.ToArray 已安装（地址 %p）", mt->methodPointer);
            } else { sys_ok = false; LOGI("【提示】MemoryStream.ToArray 查找失败"); }
        } else { sys_ok = false; LOGI("【提示】MemoryStream 类查找失败"); }

        // 附加双保险：RijndaelManaged 的 2 参加解密工厂（不存在/未重写则跳过，
        // 不影响 sys_ok——基类 SymmetricAlgorithm 的 2 参工厂内部会调 setter）
        Il2CppClass *rm = find_class_in_assemblies("System.Security.Cryptography",
                                                   "RijndaelManaged");
        if (rm) {
            const MethodInfo *md = il2cpp_class_get_method_from_name(rm, "CreateDecryptor", 2);
            if (md && md->methodPointer) {
                DobbyHook((void *)md->methodPointer, (void *)my_sys_create_dec,
                          (void **)&old_sys_create_dec);
                LOGI("【探针】RijndaelManaged.CreateDecryptor(2参) 已安装（地址 %p）", md->methodPointer);
            } else {
                LOGI("【提示】RijndaelManaged.CreateDecryptor(2参) 未找到（依赖 set_Key 路径）");
            }
            const MethodInfo *me = il2cpp_class_get_method_from_name(rm, "CreateEncryptor", 2);
            if (me && me->methodPointer) {
                DobbyHook((void *)me->methodPointer, (void *)my_sys_create_enc,
                          (void **)&old_sys_create_enc);
                LOGI("【探针】RijndaelManaged.CreateEncryptor(2参) 已安装（地址 %p）", me->methodPointer);
            }
        } else {
            LOGI("【提示】RijndaelManaged 类未找到（依赖 set_Key/set_IV 路径抓密钥）");
        }

        sys_done = sys_ok;
        if (sys_done)
            LOGI("【探针】框架层加解密 hook 安装完成（set_Key/set_IV/CryptoStream/MemoryStream 已就位）");
    }

    return sys_done;
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

            // 全量韩文捕获网：hook 字符串创建 API（版本无关）。
            // 任何托管字符串（含原生 AssetBundle 反序列化直接构造的）都要经过
            // 这两个导出函数，韩文一律入库；失败安全，装不上也不影响翻译。
            {
                void *p_new = (void *)xdl_sym(handle, "il2cpp_string_new", &sym_size);
                size_t sym_size2 = 0;
                void *p_u16 = (void *)xdl_sym(handle, "il2cpp_string_new_utf16", &sym_size2);
                if (p_new) {
                    if (DobbyHook(p_new, (void *)my_string_new, (void **)&old_string_new) == 0) {
                        // 我们自己造中文替换串时直接走 trampoline，跳过本 hook
                        il2cpp_string_new_ptr = (MyIl2CppString *(*)(const char *))old_string_new;
                        LOGI("【成功】全量韩文库已安装：il2cpp_string_new @ %p", p_new);
                    } else {
                        LOGI("【提示】il2cpp_string_new hook 安装失败，跳过（不影响翻译）");
                    }
                } else {
                    LOGI("【提示】未找到 il2cpp_string_new 导出，全量韩文库跳过");
                }
                if (p_u16) {
                    if (DobbyHook(p_u16, (void *)my_string_new_utf16, (void **)&old_string_new_utf16) == 0)
                        LOGI("【成功】全量韩文库已安装：il2cpp_string_new_utf16 @ %p", p_u16);
                    else
                        LOGI("【提示】il2cpp_string_new_utf16 hook 安装失败，跳过（不影响翻译）");
                } else {
                    LOGI("【提示】未找到 il2cpp_string_new_utf16 导出，utf16 捕获跳过");
                }
            }

            // 立即安装：self-SIGKILL 已被拦截，游戏启动完整性检测的自杀手段失效，
            // 无需再靠 sleep(25) 躲避检测窗口。启动阶段的表解密（kr.client 等）
            // 只有 hook 及时就位才能抓到 —— 这是静态解包的关键数据源。
            // hook 安装带重试：启动早期 il2cpp 程序集可能尚未加载完毕
            bool hooked = false;
            for (int retry = 0; retry < 30 && !hooked; retry++) {
                hooked = install_hooks_by_name(handle);
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
