// Created by Perfare on 2020/7/4.
// Trickcal Revive 汉化模块（重构维护版，2026-09-05）
//
// 当前活路径（实验性解密 dump / 加解密探针 / 枚举类查找已删除：热更新后剧情
// 装载原生侧化，托管层加解密探针实测全程零触发，留着只增崩溃面）：
//   1. 文本翻译：按名 hook 5 个文本入口——TMPro.TMP_Text.set_text（基类）、
//      TextMeshProUGUI/TextMeshPro 子类重写 set_text（名字牌/图鉴名实际走的
//      路径，2026-09-07 实测基类被虚分派绕过）、TMP_Text.SetText 内部方法、
//      UnityEngine.UI.Text.set_text。查 string_data.txt 字典：整句精确 →
//      去标签/空白归一化 → 术语逐词替换（数字/标点保留）→ 数字+单位词转换
//      （2026년 9월 7일 → 2026年 9月 7日）。字典支持热重载：外部修改
//      string_data.txt 后 5 秒内自动生效，无需重启游戏。
//   2. 韩文采集（增量）：set_text 钩子 + il2cpp_string_new / il2cpp_string_new_utf16
//      全量捕获网。任何托管字符串（含原生 AssetBundle 反序列化直接构造的）
//      创建时若含谚文，一律去重落盘 captured_korean.txt，供离线批量翻译。
//      注意：hook 的是导出跳板解析出的【真实实现】，见 resolve_thunk_target()。
//   3. 韩文采集（全量主力）：原生内存韩文扫描。剧场实测证明剧情文本由 AOT
//      代码在显示瞬间才构造（runtime_invoke 零新增、调用链在 libhoudini 下
//      不可靠），但文本数据加载后常驻本进程内存——直接扫可写映射提取谚文
//      UTF-8 + UTF-16LE 序列，拿全（含未显示分支）。90 秒首次自动扫，此后
//      每 120 秒自动扫（游戏流式加载数据需要时间）；scan_now 文件随时触发。
//   4. 防自杀：hook exit/_exit/kill/tgkill，拦截启动完整性检测的自毁。
//   5. 诊断：runtime_invoke 监控（唯一方法名去重日志，定位反射路径调用）。
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
#include <atomic>
#include <cstdint>
#include <string>
#include <fstream>
#include <sstream>
#include <shared_mutex>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include <cstdlib>
#include <mutex>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctime>
#include <limits.h>

extern "C" int DobbyHook(void *function_address, void *replace_call, void **origin_call);

// ==================== 自动日志落盘 ====================
// hack_start 末尾 fork 子进程跑 logcat，把本模块日志（tag=chopperhl）自动
// 写入 /sdcard/Download/chopperhl_log.txt，用户无需手动 adb logcat。
// 用 fork+execl 直接执行 /system/bin/logcat（不经过 shell），更可靠。
static void start_auto_logcat() {
    pid_t pid = fork();
    if (pid == 0) {
        // 子进程：先清缓冲，再持续写文件（阻塞直到游戏进程退出）
        execl("/system/bin/logcat", "logcat", "-c", nullptr);
        _exit(127);
    } else if (pid > 0) {
        waitpid(pid, nullptr, 0);  // 等清缓冲完成
    }
    pid = fork();
    if (pid == 0) {
        execl("/system/bin/logcat", "logcat", "-v", "time",
              "chopperhl:v", "*:S",
              "-f", "/sdcard/Download/chopperhl_log.txt", nullptr);
        _exit(127);
    }
    LOGI("【成功】自动日志已启动（logcat PID %d），写入 /sdcard/Download/chopperhl_log.txt", pid);
}

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
// 术语表：从字典抽取的纯谚文短词（人名/UI词，2~8音节），用于整句未命中时
// 的逐词替换（数字/标点/标签原样保留），解决"活动还剩3天16小时"这类模板文本。
std::unordered_map<std::string, std::string> term_map;
// 字典锁：热重载（写）与翻译查找（读）并发。读路径用 shared_lock，重载用
// unique_lock；锁只护 map 访问，严禁在持锁状态下调用 origin/创建字符串。
static std::shared_mutex g_dict_mutex;
std::unordered_set<std::string> captured_kr_texts;
static std::mutex capture_mutex;  // set_text 可能被游戏多线程并发调用

// 判断 UTF-8 字节 i 处是否为谚文音节(U+AC00-U+D7A3)，是返回字节数3，否则0
static int hangul_at(const char *s, size_t i, size_t n) {
    if (i + 3 > n) return 0;
    unsigned char b0 = (unsigned char)s[i], b1 = (unsigned char)s[i+1], b2 = (unsigned char)s[i+2];
    bool c2 = (b2 >= 0x80 && b2 <= 0xBF);
    if (b0 == 0xEA && b1 >= 0xB0 && b1 <= 0xBF && c2) return 3;
    if (b0 == 0xEB && b1 >= 0x80 && b1 <= 0xBF && c2) return 3;
    if (b0 == 0xEC && b1 >= 0x80 && b1 <= 0xBF && c2) return 3;
    if (b0 == 0xED && b1 >= 0x80 && b1 <= 0x9E && b2 >= 0x80 && b2 <= 0xA3) return 3;
    return 0;
}

// 前置声明：定义在内存扫描区（L641 附近），归一化/扫描共用
static int utf8_decode_one(const uint8_t *p, const uint8_t *e, uint32_t &cp);

// 首尾装饰性字符判定（emoji/符号/变体选择器等）。游戏文本常带前缀装饰如
// "🍬접속 시..."，归一化时剥掉，让干净字典键也能命中。
static bool is_trim_decor(uint32_t cp) {
    if (cp == ' ' || cp == '\t' || cp == '\r' || cp == '\n') return true;
    if (cp == '&' || cp == '*' || cp == '~' || cp == '^' || cp == 0xB7) return true;
    if (cp == 0xFE0F || cp == 0x200D || cp == 0x200C || cp == 0xFEFF) return true; // 变体/ZWJ/BOM
    if (cp >= 0x1F000 && cp <= 0x1FAFF) return true;                               // emoji 主区
    if (cp >= 0x2600 && cp <= 0x27BF) return true;                                 // 杂项符号/装饰箭头
    if (cp >= 0x1F100 && cp <= 0x1F1FF) return true;                               // 包围字母数字
    return false;
}

// 查找用归一化：去掉富文本标签 <...>、首尾空白与装饰字符。剧情人名同一位置
// 忽译忽不译，根因是两次 set_text 传入的串一个带 <color>/<size> 标签或尾随
// 空格、一个不带；邮件标题带 🍬/& 前缀。归一化后内容一致即可稳定命中。
static std::string normalize_for_lookup(const std::string &s) {
    std::string out;
    out.reserve(s.size());
    bool intag = false;
    for (char c : s) {
        if (c == '<') { intag = true; continue; }
        if (c == '>') { intag = false; continue; }
        if (!intag) out.push_back(c);
    }
    // 首尾按码点剥装饰
    size_t b = 0, n = out.size();
    while (b < n) {
        uint32_t cp; int w = utf8_decode_one((const uint8_t *)out.data() + b, (const uint8_t *)out.data() + n, cp);
        if (w == 0 || !is_trim_decor(cp)) break;
        b += w;
    }
    size_t e = n;
    while (e > b) {
        // 回退到上一个完整 UTF-8 序列起点
        size_t p = e - 1;
        while (p > b && ((unsigned char)out[p] & 0xC0) == 0x80) p--;
        uint32_t cp; int w = utf8_decode_one((const uint8_t *)out.data() + p, (const uint8_t *)out.data() + e, cp);
        if (w == 0 || !is_trim_decor(cp)) break;
        e = p;
    }
    if (b >= e) return "";
    return out.substr(b, e - b);
}

// 常见谚文助词（替换术语时连带省略，中文不需要）
static const std::unordered_set<std::string> g_particles = {
    "가","이","을","를","은","는","와","과","도","만","에","께","라","나","마","냐","고",
    "한테","까지","처럼","보다","부터","조차","에게","께서","에서","하고","이나","나마","랑","이랑"
};

// 整句未命中时的逐词替换：句中纯谚文连续段若命中术语表则换成中文，数字/标点/
// 空格/标签原样保留；带助词的人名（네르가→奈尔）自动剥离常见助词尾。返回是否改。
static bool apply_terms(std::string &s) {
    bool changed = false;
    size_t n = s.size(), i = 0;
    std::string out;
    out.reserve(n);
    while (i < n) {
        if (hangul_at(s.c_str(), i, n) == 0) { out.push_back(s[i]); i++; continue; }
        size_t start = i;
        while (i < n) {
            int a = hangul_at(s.c_str(), i, n);
            if (a == 0) break;
            i += a;
        }
        std::string run = s.substr(start, i - start);
        auto it = term_map.find(run);
        if (it != term_map.end()) { out += it->second; changed = true; continue; }
        // 尝试剥离 1~3 个尾音节助词（核心至少保留 2 音节）
        bool replaced = false;
        for (int strip = 1; strip <= 3 && run.size() >= (size_t)(strip + 2) * 3; strip++) {
            std::string core = run.substr(0, run.size() - strip * 3);
            std::string tail = run.substr(run.size() - strip * 3);
            auto ti = term_map.find(core);
            if (ti != term_map.end() && g_particles.count(tail)) {
                out += ti->second;   // 省略助词
                changed = true; replaced = true; break;
            }
        }
        if (!replaced) out += run;
    }
    // 数字+单位词直转：紧跟在 ASCII 数字后的单音节单位词无歧义（년=年/월=月/
    // 일=日/시=时/분=分），术语表不收单音节词（太容易误替换），这里做定点替换。
    // "발송 일자: 2026년 9월 7일" → "발송 일자: 2026年 9月 7日"
    for (size_t i = 0; i + 3 < out.size(); i++) {
        if (out[i] < '0' || out[i] > '9') continue;
        // 跳过连续数字
        size_t d = i;
        while (d < out.size() && out[d] >= '0' && out[d] <= '9') d++;
        if (d + 3 > out.size()) { i = d; continue; }
        const unsigned char u0 = (unsigned char)out[d], u1 = (unsigned char)out[d+1], u2 = (unsigned char)out[d+2];
        const char *zh = nullptr;
        if (u0==0xEB && u1==0x85 && u2==0x84) zh = "年";      // 년
        else if (u0==0xEC && u1==0x9B && u2==0x94) zh = "月";  // 월
        else if (u0==0xEC && u1==0x9D && u2==0xBC) zh = "日";  // 일
        else if (u0==0xEC && u1==0x8B && u2==0x9C) zh = "时";  // 시
        else if (u0==0xEB && u1==0xB6 && u2==0x84) zh = "分";  // 분
        if (zh) {
            out.replace(d, 3, zh);
            changed = true;
        }
        i = d;
    }
    if (changed) s.swap(out);
    return changed;
}

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

#define DICT_PATH "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/string_data.txt"

// 解析字典文件并重建两张表。调用方必须已持有 g_dict_mutex 写锁（或启动期无并发）。
// 返回读入的词条数。
static int load_dict_unlocked() {
    translation_map.clear();
    term_map.clear();
    std::ifstream file(DICT_PATH);
    if (!file.is_open()) { LOGI("【汉化提示】未能打开字典文件！"); return 0; }
    std::string line;
    int count = 0;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        // 跳过注释行
        if (line[0] == '#') continue;
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = unescape_newlines(line.substr(0, pos));
            std::string val = unescape_newlines(line.substr(pos + 1));
            if (key.empty()) continue;
            translation_map[key] = val;
            count++;
            // 纯谚文短词（2~8 音节、无空格/标点/标签）进术语表，供逐词替换
            if (key.size() >= 6 && key.size() <= 24) {
                bool pure = true;
                for (size_t j = 0; j < key.size();) {
                    int a = hangul_at(key.c_str(), j, key.size());
                    if (a == 0) { pure = false; break; }
                    j += a;
                }
                if (pure) term_map[key] = val;
            }
        }
    }
    file.close();
    return count;
}

void load_translation_dict() {
    std::unique_lock<std::shared_mutex> lk(g_dict_mutex);
    int count = load_dict_unlocked();
    LOGI("【汉化提示】字典加载成功！共读入 %d 条翻译词条（含 %d 个术语短词）。",
         count, (int)term_map.size());
}

// 字典热重载监视线程：每 5 秒检查 string_data.txt 的 mtime/size，变化即重载。
// 这样"改字典 → adb push → 游戏内 5 秒生效"，无需重启游戏。
static void start_dict_watcher() {
    std::thread([]{
        struct stat st{};
        bool have = (stat(DICT_PATH, &st) == 0);
        time_t mt = have ? st.st_mtime : 0;
        off_t sz = have ? st.st_size : 0;
        while (true) {
            sleep(5);
            struct stat cur{};
            if (stat(DICT_PATH, &cur) != 0) continue;
            if (!have || cur.st_mtime != mt || cur.st_size != sz) {
                mt = cur.st_mtime; sz = cur.st_size; have = true;
                std::unique_lock<std::shared_mutex> lk(g_dict_mutex);
                int n = load_dict_unlocked();
                LOGI("【字典】检测到 string_data.txt 更新，热重载完成：%d 条（含 %d 个术语短词）",
                     n, (int)term_map.size());
            }
        }
    }).detach();
    LOGI("【字典】热重载监视线程已启动（每 5 秒检查一次文件变动）");
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
        // 文件中 \n 是字面两字符（\ 和 n），需还原为真实换行符(0x0A)
        // 才能与运行时捕获的字符串格式一致，否则多行文本每次都被重复采集
        size_t pos = 0;
        while ((pos = line.find("\\n", pos)) != std::string::npos) {
            line.replace(pos, 2, "\n");
            pos += 1;
        }
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
// 去重核心（UTF-8 输入），供本函数与内存扫描共用。
static bool record_korean_utf8(const std::string &text) {
    if (text.size() < 3 || text.size() > 4096) return false;
    std::lock_guard<std::mutex> lk(capture_mutex);
    return captured_kr_texts.insert(text).second;
}

// 追加写入一条捕获记录（换行转义为字面 \n）。batch 为空则逐条开关文件。
static void write_captured_line(const std::string &text, FILE *batch) {
    std::string safe = text;
    size_t p = 0;
    while ((p = safe.find('\n', p)) != std::string::npos) {
        safe.replace(p, 1, "\\n");
        p += 2;
    }
    std::lock_guard<std::mutex> lk(capture_mutex);
    if (batch) {
        fprintf(batch, "%s\n", safe.c_str());
    } else {
        FILE *f = fopen("/sdcard/Download/captured_korean.txt", "a");
        if (f) { fprintf(f, "%s\n", safe.c_str()); fclose(f); }
    }
}

static bool record_captured_korean(const char16_t *chars, int32_t len, const char *tag) {
    // len>=1：单音节韩文（네/예/응 等）也是有效文本；>1024 视为非文本载荷跳过
    if (!chars || len <= 0 || len > 1024) return false;
    if (!contains_korean(chars, len)) return false;
    std::string text = utf16_to_utf8(chars, len);
    bool is_new = record_korean_utf8(text);
    if (!is_new) return false;
    write_captured_line(text, nullptr);
    static int total = 0;
    int n = ++total;
    // 日志策略：#1~#20 逐条（足够看到启动期活动）；之后每 30 秒打一次心跳
    // 汇总（仅在有新增时触发），每 500 条打里程碑。避免长时间静默让人无法
    // 区分"没捕获到"与"捕获正常但都被去重"。
    static int last_beat_total = 0;
    static time_t last_log_time = 0;
    time_t now = time(nullptr);
    if (n <= 20) {
        LOGI("【%s】#%d %s", tag, n, text.c_str());
        last_log_time = now;
        last_beat_total = n;
    } else if (n % 500 == 0) {
        LOGI("【%s】#%d %s", tag, n, text.c_str());
        last_log_time = now;
        last_beat_total = n;
    } else if (now - last_log_time >= 30) {
        LOGI("【%s心跳】累计新增 %d 条（近30秒 +%d）", tag, n, n - last_beat_total);
        last_beat_total = n;
        last_log_time = now;
    }
    // else: 30 秒内已有日志输出且非里程碑，静默避免刷屏
    return true;
}

// 第一次捕获到韩文时，打印调用栈
static bool callstack_printed = false;
// 翻译匹配总次数（日志限流用）
static std::atomic<int> g_match_count{0};

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

        // 查字典翻译：① 原文精确匹配；② 去标签/空白/装饰后归一化匹配（治人名
        // 忽译忽不译、邮件标题带 🍬 前缀）；③ 整句未命中时逐词替换术语 +
        // 数字+单位词转换（治"3天16小时""2026년 9월 7일"这类模板）。
        // 锁只护 map 读取，在调用 origin / 创建字符串前已释放。
        std::string translated;
        bool matched = false;
        {
            std::shared_lock<std::shared_mutex> lk(g_dict_mutex);
            auto it = translation_map.find(original_text);
            if (it == translation_map.end()) {
                std::string norm = normalize_for_lookup(original_text);
                if (!norm.empty() && norm != original_text) {
                    auto jt = translation_map.find(norm);
                    if (jt != translation_map.end()) it = jt;
                }
            }
            if (it != translation_map.end()) {
                translated = it->second; matched = true;
            } else if (contains_korean(il2cpp_string->chars, il2cpp_string->length)) {
                std::string tmp = original_text;
                if (apply_terms(tmp)) { translated = tmp; matched = true; }
            }
        }
        if (matched && il2cpp_string_new_ptr != nullptr) {
            MyIl2CppString *new_string = il2cpp_string_new_ptr(translated.c_str());
            if (new_string != nullptr) {
                // 匹配日志限流：字典大了之后每次匹配都打会刷爆 logcat。
                // 前 200 条逐条打，之后每 1000 条打 1 条。
                int n = ++g_match_count;
                if (n <= 200 || n % 1000 == 0)
                    LOGI("【汉化匹配】%s -> %s（第 %d 次）", original_text.c_str(), translated.c_str(), n);
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

// ---- TMP 子类重写路径（2026-09-07 名字牌不翻译修复）----
// 实测：对话正文（走 legacy UI.Text）能翻译，但剧情名字牌/图鉴角色名
// （TMP UGUI 组件）永远不翻译——部分 TMP 版本中 TextMeshProUGUI /
// TextMeshPro 重写(override)了 text 属性，游戏给这类组件赋值时虚分派到
// 子类 set_text，完全不经过我们挂钩的基类 TMP_Text.set_text。
// 另外部分代码走 TMP_Text.SetText(string) 内部方法，同样绕过属性 setter。
// 三个入口全部挂上，各自转发到各自原函数；重复翻译是安全的（中文不含
// 谚文，内层钩子查不到字典直接放行）。
static set_text_fn old_tmp_ugi_set_text  = nullptr;  // TextMeshProUGUI.set_text
static set_text_fn old_tmp3d_set_text    = nullptr;  // TextMeshPro.set_text
static set_text_fn old_tmptext_settext   = nullptr;  // TMP_Text.SetText(string)

void my_tmp_ugi_set_text(void *__this, MyIl2CppString *il2cpp_string) {
    process_and_forward(__this, il2cpp_string, old_tmp_ugi_set_text);
}

void my_tmp3d_set_text(void *__this, MyIl2CppString *il2cpp_string) {
    process_and_forward(__this, il2cpp_string, old_tmp3d_set_text);
}

void my_tmptext_settext(void *__this, MyIl2CppString *il2cpp_string) {
    process_and_forward(__this, il2cpp_string, old_tmptext_settext);
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

// 线程局部：当前正在执行的 invoke 方法名（诊断用途，配合 invoke 日志排查
// 哪些调用经反射路径；已证实剧情文本构造不经此路径）
static thread_local const char *g_current_invoke = nullptr;

// 帧指针走链调用栈在 string_new 钩子上实测输出垃圾（libhoudini 翻译层下
// FP 链不可靠，RVA 恒为同一值），已于 2026-09-05 移除；invoke 关联同样
// 证实剧情构造不走 runtime_invoke。定位职责已由【原生内存韩文扫描】接管。

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

// ==================== 原生内存韩文扫描（全量文本采集，2026-09-05）====================
// 剧场定位结论：剧情对白由 AOT 代码在【显示瞬间】才经 il2cpp_string_new 构造
// （播放全程 runtime_invoke 唯一方法零新增），逐行捕获必须逐句观看；但大厅
// 启动期数百个混淆协程批量装载数据表，剧情/图鉴/技能等文本作为原生 UTF-8
// 字节常驻本进程堆/匿名映射中。直接扫描自身可写内存提取谚文序列，可一次性
// 拿到全部已加载文本（含未显示分支），版本无关、只读零风险、不依赖任何符号。
// 触发：hack 完成后 90 秒自动扫一次（大厅表装载完毕）；之后每 5 秒检查
// /sdcard/Download/scan_now 触发文件（存在即扫描并删除）——用户在共享目录
// 新建该空文件即可随时触发（如进入某集剧情后扫一次拿全分支脚本）。

// UTF-8 解码一个码点；返回字节数，非法返回 0
static int utf8_decode_one(const uint8_t *p, const uint8_t *e, uint32_t &cp) {
    if (p >= e) return 0;
    uint8_t b = p[0];
    if (b < 0x80) { cp = b; return 1; }
    int n; uint32_t v;
    if      ((b & 0xE0) == 0xC0) { n = 2; v = b & 0x1F; }
    else if ((b & 0xF0) == 0xE0) { n = 3; v = b & 0x0F; }
    else if ((b & 0xF8) == 0xF0) { n = 4; v = b & 0x07; }
    else return 0;
    if (p + n > e) return 0;
    for (int k = 1; k < n; k++) {
        if ((p[k] & 0xC0) != 0x80) return 0;
        v = (v << 6) | (p[k] & 0x3F);
    }
    if ((n == 2 && v < 0x80) || (n == 3 && v < 0x800) || (n == 4 && v < 0x10000)) return 0;
    if (v > 0x10FFFF) return 0;
    cp = v;
    return n;
}

static bool is_hangul_syllable(uint32_t cp) { return cp >= 0xAC00 && cp <= 0xD7A3; }
// run 内允许的字符：可打印 ASCII + 谚文音节/字母 + 韩文常用标点区。
// 不收其他文字区（拉丁扩展/西里尔/阿拉伯/CJK 汉字等）——内存里紧邻的
// 键名字符串（如 Character_Beni_Ep03_026）和外文垃圾会粘进正文，
// 收紧后它们会断开 run 被自然丢弃（实测出现过阿拉伯字符粘连）。
static bool is_run_char(uint32_t cp) {
    if (cp >= 0x20 && cp < 0x7F) return true;          // ASCII 可打印
    if (cp >= 0xAC00 && cp <= 0xD7A3) return true;     // 谚文音节
    if (cp >= 0x1100 && cp <= 0x11FF) return true;     // 谚文字母
    if (cp >= 0x3130 && cp <= 0x318F) return true;     // 谚文兼容字母
    if (cp >= 0x3000 && cp <= 0x303F) return true;     // CJK 标点（…、「」等）
    if (cp >= 0x2010 && cp <= 0x2027) return true;     // 通用标点（–—''""…）
    if (cp >= 0xFF00 && cp <= 0xFFEF) return true;     // 全角形式
    return false;
}

// 扫描一段内存的 UTF-8 文本，提取含 ≥2 个谚文音节的 run
static void scan_region_utf8(const uint8_t *p, size_t len,
                             int &fresh, FILE *batch) {
    const uint8_t *q = p, *e = p + len;
    std::string run;
    run.reserve(256);
    int hangul = 0;
    auto flush = [&]() {
        if (hangul >= 2 && run.size() >= 3 && run.size() <= 4096) {
            size_t b = 0, t = run.size();
            while (b < t && (run[b] == ' ' || run[b] == '\t')) b++;
            while (t > b && (run[t-1] == ' ' || run[t-1] == '\t')) t--;
            std::string text = run.substr(b, t - b);
            if (text.size() >= 3 && record_korean_utf8(text)) {
                fresh++;
                write_captured_line(text, batch);
            }
        }
        run.clear();
        hangul = 0;
    };
    while (q < e) {
        uint32_t cp;
        int n = utf8_decode_one(q, e, cp);
        if (n == 0 || !is_run_char(cp)) { flush(); q += (n == 0 ? 1 : n); continue; }
        if (is_hangul_syllable(cp)) hangul++;
        run.append((const char *)q, n);
        if (run.size() > 4096) flush();
        q += n;
    }
    flush();
}

// 扫描一段内存的 UTF-16LE 文本（IL2CPP string 对象的数据区）
// IL2CPP string 布局: klass@0x00(8B) monitor@0x08(8B) length@0x10(4B) chars@0x14
// 在 GC 堆中 string 对象密集排列，chars 数据连续分布在堆内存里。
// UTF-16LE 谚文音节 U+AC00-U+D7A3 = 字节对 [low, 0xAC-0xD7]。
static void scan_region_utf16le(const uint8_t *p, size_t len,
                                int &fresh, FILE *batch) {
    if (len < 4) return;
    const uint8_t *q = p, *e = p + len - 1;  // -1: 需要完整 2 字节对
    // UTF-16LE char → 码点
    auto decode_u16 = [](const uint8_t *q, uint32_t &cp) -> int {
        uint16_t v = q[0] | (q[1] << 8);
        cp = v;
        return 2;
    };
    auto is_run_u16 = [](uint32_t cp) -> bool {
        if (cp >= 0x20 && cp < 0x7F) return true;
        if (cp >= 0xAC00 && cp <= 0xD7A3) return true;
        if (cp >= 0x1100 && cp <= 0x11FF) return true;
        if (cp >= 0x3130 && cp <= 0x318F) return true;
        if (cp >= 0x3000 && cp <= 0x303F) return true;
        if (cp >= 0x2010 && cp <= 0x2027) return true;
        if (cp >= 0xFF00 && cp <= 0xFFEF) return true;
        return false;
    };
    std::u16string run16;
    run16.reserve(256);
    int hangul = 0;
    auto flush = [&]() {
        if (hangul >= 4 && run16.size() >= 4 && run16.size() <= 4096) {
            // UTF-16 → UTF-8
            std::string text = utf16_to_utf8(run16.data(), (int32_t)run16.size());
            if (text.size() >= 3 && record_korean_utf8(text)) {
                fresh++;
                write_captured_line(text, batch);
            }
        }
        run16.clear();
        hangul = 0;
    };
    while (q < e) {
        // 跳过奇数对齐：UTF-16 必须从偶数地址开始才有效。
        // 但在 GC 堆中 string 对象按 8/16 字节对齐，chars 起始在偶数地址。
        // 如果当前地址是奇数且第一个字节看起来不是有效 UTF-16 起始，跳一字节。
        uint32_t cp;
        int n = decode_u16(q, cp);
        if (!is_run_u16(cp)) { flush(); q += 2; continue; }
        if (cp >= 0xAC00 && cp <= 0xD7A3) hangul++;
        run16.push_back((char16_t)cp);
        if (run16.size() > 4096) flush();
        q += 2;
    }
    flush();
}

// 扫描所有可写映射提取韩文。返回本轮新增总数；out_utf8/out_utf16 可选带回分项。
static int scan_memory_for_korean(const char *why, int *out_utf8 = nullptr, int *out_utf16 = nullptr) {
    LOGI("【内存扫描】开始（%s）...", why);
    FILE *mf = fopen("/proc/self/maps", "r");
    if (!mf) { LOGI("【内存扫描】无法打开 /proc/self/maps，放弃"); return 0; }
    FILE *batch = fopen("/sdcard/Download/captured_korean.txt", "a");
    if (!batch) { fclose(mf); LOGI("【内存扫描】无法打开输出文件，放弃"); return 0; }
    setvbuf(batch, nullptr, _IONBF, 0);

    char line[1024];
    int regions = 0, fresh_utf8 = 0, fresh_utf16 = 0;
    size_t scanned = 0, next_progress = 512ull << 20;
    while (fgets(line, sizeof(line), mf)) {
        unsigned long long s_ = 0, e_ = 0, inode = 0;
        char perms[8] = {0};
        int po = -1;
        if (sscanf(line, "%llx-%llx %4s %*s %*s %llu %n",
                   &s_, &e_, perms, &inode, &po) < 4) continue;
        uintptr_t start = (uintptr_t)s_, end = (uintptr_t)e_;
        if (end <= start) continue;
        size_t len = end - start;
        if (len < 4096 || len > (1ull << 30)) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;

        bool has_path = false;
        if (po > 0 && po < (int)sizeof(line)) {
            const char *path = line + po;
            while (*path == ' ') path++;
            has_path = (*path != '\0' && *path != '\n');
            if (has_path && !strstr(path, "epidgames")) continue;
        }

        regions++;
        // 先扫 UTF-8（原始数据文件/JSON/CSV），再扫 UTF-16LE（IL2CPP string 对象）
        scan_region_utf8((const uint8_t *)start, len, fresh_utf8, batch);
        scan_region_utf16le((const uint8_t *)start, len, fresh_utf16, batch);
        scanned += len;
        if (scanned >= next_progress) {
            LOGI("【内存扫描】进度 %zu MB，UTF-8 +%d UTF-16 +%d",
                 scanned >> 20, fresh_utf8, fresh_utf16);
            next_progress += 512ull << 20;
        }
    }
    fclose(batch);
    fclose(mf);
    LOGI("【内存扫描】完成（%s）：区域 %d 个，扫描 %zu MB，新增 UTF-8 %d 条 + UTF-16 %d 条",
         why, regions, scanned >> 20, fresh_utf8, fresh_utf16);
    if (out_utf8) *out_utf8 = fresh_utf8;
    if (out_utf16) *out_utf16 = fresh_utf16;
    return fresh_utf8 + fresh_utf16;
}

// 扫描线程：90 秒后首次自动扫；自动轮间隔自适应——收益大（新数据多）保持
// 120 秒，收益小则逐倍退避至 30 分钟，避免游戏期周期性 CPU 尖峰。手动
// scan_now 触发不受间隔影响，且会把自动轮拉回高频。每次扫描都走全量去重，
// 已有条目不会重复写入——只增不丢。
static void start_memory_scanner() {
    std::thread([]{
        sleep(90);
        int round = 0;
        int interval = 120;  // 自动轮间隔（秒），自适应调整
        while (true) {
            round++;
            char why[64];
            snprintf(why, sizeof(why), "自动第%d轮", round);
            int fresh_utf8 = 0, fresh_utf16 = 0;
            int fresh = scan_memory_for_korean(why, &fresh_utf8, &fresh_utf16);
            if (fresh >= 1000) interval = 120;                 // 收益大：保持高频
            else if (fresh > 0) { /* 收益一般：保持当前间隔 */ }
            else interval = interval * 2 < 1800 ? interval * 2 : 1800;  // 零收益：退避
            // 期间每 5 秒检查 scan_now 触发文件；任何手动触发后回到高频
            int ticks = interval / 5;
            for (int i = 0; i < ticks; i++) {
                sleep(5);
                FILE *t = fopen("/sdcard/Download/scan_now", "rb");
                if (t) {
                    fclose(t);
                    remove("/sdcard/Download/scan_now");
                    scan_memory_for_korean("手动触发(scan_now)");
                    interval = 120;
                }
            }
        }
    }).detach();
    LOGI("【内存扫描】扫描线程已启动（90 秒后首次扫描；间隔随收益自适应 120 秒~30 分钟；"
         "共享目录新建 scan_now 文件可随时触发）");
}

// ==================== runtime_invoke 监控（定位剧情加载函数）====================
// il2cpp_runtime_invoke 是 IL2CPP 运行时调用托管方法的入口（反射调用、Unity
// 事件系统、协程等经此路径）。hook 后记录所有被调用方法的名字（去重），用户
// 进剧场选一集剧情时，日志中新增的方法名即为加载剧情数据的候选入口函数。
// 注意：IL2CPP 直接编译的方法调用不走 runtime_invoke（A→B 是直接 call），但
// Unity 内部系统（事件/协程/资源加载）很多经此调用，足以定位触发点。

typedef const char *(*method_get_name_fn)(const void *method);
typedef void *(*runtime_invoke_fn)(const void *method, void *object,
                                   void **params, void **exc);
// 参数类型校验用（hack_start 里 xdl_sym 解析；SetText 有 string/StringBuilder
// 两个 1 参重载，按名查找可能命中 StringBuilder 版本，不校验会按错误布局读内存）
typedef const void *(*method_get_param_fn)(const void *method, uint32_t index);
typedef char *(*type_get_name_fn)(const void *type);
static method_get_name_fn  il2cpp_method_get_name_ptr = nullptr;
static method_get_param_fn il2cpp_method_get_param_ptr = nullptr;
static type_get_name_fn    il2cpp_type_get_name_ptr = nullptr;
static runtime_invoke_fn   old_runtime_invoke = nullptr;
static std::unordered_set<std::string> g_invoke_seen;
static std::mutex           g_invoke_mutex;
static int g_invoke_total  = 0;
static int g_invoke_unique = 0;
static time_t g_invoke_last_log = 0;

static void *my_runtime_invoke(const void *method, void *object,
                               void **params, void **exc) {
    // 在调原函数之前记录方法名，因为 string_new 会在原函数内部被调用
    const char *name = nullptr;
    if (il2cpp_method_get_name_ptr && method) {
        name = il2cpp_method_get_name_ptr(method);
        g_current_invoke = name;
    }

    void *result = old_runtime_invoke
                       ? old_runtime_invoke(method, object, params, exc)
                       : nullptr;
    g_current_invoke = nullptr;

    if (name) {
        g_invoke_total++;
        bool is_new = false;
        {
            std::lock_guard<std::mutex> lk(g_invoke_mutex);
            is_new = g_invoke_seen.insert(std::string(name)).second;
            if (is_new) g_invoke_unique++;
        }
        // 不再限制上限：剧情播放期间新增的方法名才是关键，不能被启动期的 500 个挤掉
        if (is_new)
            LOGI("【invoke】#%d %s", g_invoke_unique, name);
        time_t now = time(nullptr);
        if (now - g_invoke_last_log >= 30) {
            LOGI("【invoke心跳】总调用 %d 次，唯一方法 %d 个",
                 g_invoke_total, g_invoke_unique);
            g_invoke_last_log = now;
        }
    }
    return result;
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
        // 防重复挂钩：类没有独立重写时，按名查找会沿继承链找到基类方法——
        // 其入口已被我们先前的钩子内联补丁覆盖。对已补丁地址再挂 Dobby 会把
        // 跳转数据当原始指令生成 trampoline → 无限递归栈溢出。视为已覆盖。
        if (already_dobby_patched((void *)method->methodPointer)) {
            LOGI("【提示】%s.%s.%s 入口已被挂钩（无独立重写，继承基类），跳过", ns, cls, method_name);
            return true;
        }
        // SetText 重载歧义防护：TMP_Text 有 SetText(string) 与
        // SetText(StringBuilder) 两个 1 参重载，按名+参数个数可能命中后者，
        // 按 Il2CppString 布局读 StringBuilder 会崩。必须校验首参是 string。
        if (strcmp(method_name, "SetText") == 0) {
            bool is_string = false;
            if (il2cpp_method_get_param_ptr && il2cpp_type_get_name_ptr) {
                const void *ptype = il2cpp_method_get_param_ptr(method, 0);
                if (ptype) {
                    // 返回串由 il2cpp 分配，仅调用数次，刻意不释放（避免依赖 il2cpp_free）
                    char *tn = il2cpp_type_get_name_ptr(ptype);
                    if (tn) is_string = (strcmp(tn, "System.String") == 0);
                }
            }
            if (!is_string) {
                LOGI("【提示】%s.%s.%s 首参不是 string（命中 StringBuilder 重载），跳过", ns, cls, method_name);
                return false;
            }
        }
        DobbyHook((void *)method->methodPointer, replace_func, origin_func);
        LOGI("【成功】%s.%s.%s Hook 完成（按名查找，地址 %p）", ns, cls, method_name, method->methodPointer);
        return true;
    }
    LOGI("【提示】未找到 %s.%s（该组件可能未使用）", ns, cls);
    return false;
}

// 返回 true 表示关键文本 hook（TMP 主路径）已就绪；可安全重试，已装的不会重装。
// 文本翻译入口共 5 个：TMP 基类 set_text、TMP UGUI/3D 子类重写 set_text、
// TMP_Text.SetText 内部方法、legacy UI.Text set_text。名字牌/图鉴名走子类
// 重写路径（2026-09-07 实测基类被绕过），必须全部覆盖。
bool install_hooks_by_name() {
    static bool tmp_done = false;     // TMP_Text.set_text（基类）
    static bool ugi_done = false;     // legacy uGUI Text（部分列表/旧UI使用）
    static bool tmp_ugi_done = false; // TextMeshProUGUI.set_text（子类重写）
    static bool tmp3d_done = false;   // TextMeshPro.set_text（3D，附加）
    static bool settext_done = false; // TMP_Text.SetText（内部路径，附加）

    if (!tmp_done)
        tmp_done = hook_text_method("TMPro", "TMP_Text", "set_text",
                                    (void *)my_set_text, (void **)&old_set_text);
    if (!ugi_done)
        ugi_done = hook_text_method("UnityEngine.UI", "Text", "set_text",
                                    (void *)my_ugi_set_text, (void **)&old_ugi_set_text);
    if (!tmp_ugi_done)
        tmp_ugi_done = hook_text_method("TMPro", "TextMeshProUGUI", "set_text",
                                        (void *)my_tmp_ugi_set_text, (void **)&old_tmp_ugi_set_text);
    if (!tmp3d_done)
        tmp3d_done = hook_text_method("TMPro", "TextMeshPro", "set_text",
                                      (void *)my_tmp3d_set_text, (void **)&old_tmp3d_set_text);
    if (!settext_done)
        settext_done = hook_text_method("TMPro", "TMP_Text", "SetText",
                                        (void *)my_tmptext_settext, (void **)&old_tmptext_settext);

    if (ugi_done)
        LOGI("【成功】legacy UI.Text 附加 Hook 生效，覆盖更多文本组件。");
    if (tmp_ugi_done)
        LOGI("【成功】TextMeshProUGUI.set_text 已挂钩——名字牌/图鉴名修复路径生效。");

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

            // 一次性任务：加载翻译字典 + 预加载已捕获文本（去重）+ 字典热重载监视
            load_translation_dict();
            preload_captured_texts();
            start_dict_watcher();

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

            // runtime_invoke 监控（定位剧情加载函数）：绑定 method_get_name +
            // hook runtime_invoke 的真实实现，记录所有被调用的方法名（去重）。
            // 失败安全，装不上不影响翻译和捕获。
            {
                size_t sz_ri = 0;
                void *sym_mgn = xdl_sym(handle, "il2cpp_method_get_name", &sz_ri);
                if (sym_mgn) {
                    il2cpp_method_get_name_ptr = (method_get_name_fn)sym_mgn;
                    LOGI("【invoke】il2cpp_method_get_name 绑定 %p", sym_mgn);
                } else {
                    LOGI("【提示】il2cpp_method_get_name 未找到，invoke 监控跳过");
                }

                // SetText 重载歧义防护所需的参数类型校验 API（缺失时 SetText 跳过不挂）
                size_t sz_p = 0, sz_t = 0;
                void *sym_mgp = xdl_sym(handle, "il2cpp_method_get_param", &sz_p);
                void *sym_tgn = xdl_sym(handle, "il2cpp_type_get_name", &sz_t);
                if (sym_mgp) il2cpp_method_get_param_ptr = (method_get_param_fn)sym_mgp;
                if (sym_tgn) il2cpp_type_get_name_ptr = (type_get_name_fn)sym_tgn;
                if (sym_mgp && sym_tgn)
                    LOGI("【提示】参数类型校验 API 已就绪（method_get_param/type_get_name）");
                else
                    LOGI("【提示】参数类型校验 API 不可用，SetText 附加钩子将跳过");

                size_t sz_rinv = 0;
                void *sym_ri = xdl_sym(handle, "il2cpp_runtime_invoke", &sz_rinv);
                if (sym_mgn && sym_ri) {
                    uintptr_t base = get_module_base("libil2cpp.so");
                    void *t_ri = resolve_thunk_target(sym_ri, base);
                    if (t_ri && !already_dobby_patched(t_ri)) {
                        if (DobbyHook(t_ri, (void *)my_runtime_invoke,
                                      (void **)&old_runtime_invoke) == 0)
                            LOGI("【成功】runtime_invoke 监控已安装 @ %p", t_ri);
                        else
                            LOGI("【提示】runtime_invoke hook 失败，监控跳过");
                    }
                } else {
                    LOGI("【提示】il2cpp_runtime_invoke 符号未找到，监控跳过");
                }
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

            // 启动自动日志落盘：fork 子进程跑 logcat，把 chopperhl 标签日志写入
            // /sdcard/Download/chopperhl_log.txt，用户无需手动 adb logcat。
            start_auto_logcat();

            // 启动原生内存韩文扫描线程（90 秒后自动扫大厅；scan_now 文件随时触发）。
            // 全量采集主力：大厅表装载后扫一次即可拿到大部分游戏文本。
            start_memory_scanner();

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

// root 版（Zygisk / NativeBridge 流程）需要本 JNI_OnLoad：x86 模拟器上 arm
// 桥接库被 NativeBridgeLoad 以 getTrampoline("JNI_OnLoad") 方式调用，reserved
// 携带 game_data_dir。免 root 独立版由 standalone_entry.cpp 提供自己的
// JNI_OnLoad（System.loadLibrary 时 reserved 为 null，且需更早装 exit blocker、
// 释放 assets 字典），此时用 HACK_STANDALONE 排除本实现避免符号冲突。
#if defined(__arm__) || defined(__aarch64__)
#ifndef HACK_STANDALONE
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    auto game_data_dir = (const char *)reserved;
    std::thread hack_thread(hack_start, game_data_dir);
    hack_thread.detach();
    return JNI_VERSION_1_6;
}
#endif
#endif
