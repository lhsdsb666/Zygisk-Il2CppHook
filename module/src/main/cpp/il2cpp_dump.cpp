//
// Created by Perfare on 2020/7/4.
//

#include "il2cpp_dump.h"
#include <dlfcn.h>
#include <cstdlib>
#include <cstring>
#include <cinttypes>
#include <string>
#include <vector>
#include <sstream>
#include <fstream>
#include <unistd.h>
#include "xdl.h"
#include "log.h"
#include "il2cpp-tabledefs.h"
#include "il2cpp-class.h"


#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API


#include "dobby.h"
#include <atomic>
static uint64_t il2cpp_base = 0;

void il2cpp_dump();

void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                      \
    n = (r (*) p)xdl_sym(handle, #n, nullptr); \
    if(!n) {                                   \
        LOGW("api not found %s", #n);          \
    }                                          \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

// =============================================================================
// 就绪检测：hook il2cpp 运行时的初始化入口。
//
// 【为什么不能轮询 API】libil2cpp.so 刚被 dlopen（其 JNI_OnLoad 阶段）时，
// 运行时全局状态（domain、线程表、TLS）全为空。此时外部线程直接调用
// il2cpp_domain_get() / il2cpp_is_vm_thread() 会在库内部空指针解引用
// SIGSEGV（实测两次：v3 在 libunity.so 侧崩，v4 在 libil2cpp.so 内崩）。
// 所以不能用"调 API 探测"的方式等就绪。
//
// 【做法】libunity 启动时必定调用 il2cpp_init / il2cpp_init_utf16 完成
// 运行时初始化。我们在库一映射就 hook 这两个入口（只改代码、不调用任何
// il2cpp 函数），初始化在 Unity 主线程完成后回调置位，工作线程被唤醒后
// 再做 domain_get / thread_attach，此时一切安全。
// =============================================================================
static std::atomic<bool> g_il2cpp_runtime_ready{false};
typedef int (*il2cpp_init_fn)(const char *);
typedef int (*il2cpp_init_utf16_fn)(const Il2CppChar *);
static il2cpp_init_fn        g_orig_il2cpp_init = nullptr;
static il2cpp_init_utf16_fn  g_orig_il2cpp_init_u16 = nullptr;

static int my_il2cpp_init(const char *domain_name) {
    int r = g_orig_il2cpp_init ? g_orig_il2cpp_init(domain_name) : -1;
    LOGI("【il2cpp】il2cpp_init 返回 %d —— 运行时初始化完成。", r);
    g_il2cpp_runtime_ready = true;
    return r;
}
static int my_il2cpp_init_utf16(const Il2CppChar *domain_name) {
    int r = g_orig_il2cpp_init_u16 ? g_orig_il2cpp_init_u16(domain_name) : -1;
    LOGI("【il2cpp】il2cpp_init_utf16 返回 %d —— 运行时初始化完成。", r);
    g_il2cpp_runtime_ready = true;
    return r;
}

void il2cpp_api_init(void *handle) {
    LOGI("il2cpp_handle: %p", handle);
    init_il2cpp_api(handle);
    if (il2cpp_domain_get_assemblies) {
        Dl_info dlInfo;
        if (dladdr((void *) il2cpp_domain_get_assemblies, &dlInfo)) {
            il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
        }
        LOGI("il2cpp_base: %" PRIx64"", il2cpp_base);
    } else {
        LOGE("Failed to initialize il2cpp api.");
        return;
    }

    // 安装就绪钩子（仅打补丁，不调用任何 il2cpp 运行时函数）
    if (il2cpp_init) {
        DobbyHook((void *) il2cpp_init, (void *) my_il2cpp_init,
                  (void **) &g_orig_il2cpp_init);
    }
    if (il2cpp_init_utf16) {
        DobbyHook((void *) il2cpp_init_utf16, (void *) my_il2cpp_init_utf16,
                  (void **) &g_orig_il2cpp_init_u16);
    }
    LOGI("il2cpp_init 就绪钩子已安装: init=%d utf16=%d",
         il2cpp_init ? 1 : 0, il2cpp_init_utf16 ? 1 : 0);

    int wait = 0;
    while (!g_il2cpp_runtime_ready.load()) {
        if (++wait > 120) {
            // 兜底：理论上注入极早时 il2cpp_init 可能在我们 hook 之前就已
            // 调用完毕。超时后按"已就绪"尝试，domain_get 前再判空保护。
            LOGE("等待 il2cpp_init 事件超时（120s），按运行时已就绪继续尝试。");
            break;
        }
        if (wait == 1 || wait % 10 == 0)
            LOGI("Waiting for il2cpp runtime init... (%d s)", wait);
        sleep(1);
    }
    if (g_il2cpp_runtime_ready.load()) {
        LOGI("il2cpp runtime ready (init event after %d s).", wait);
        sleep(2);  // 让 Unity 主线程走出 init 临界区
    }

    // 运行时初始化已完成，以下调用安全
    auto domain = il2cpp_domain_get();
    if (!domain) {
        LOGE("il2cpp_domain_get() 返回空，放弃 hook 安装（游戏可正常运行，仅无汉化）。");
        return;
    }
    il2cpp_thread_attach(domain);
    LOGI("工作线程已 attach 到 il2cpp domain=%p。", domain);
}

// =============================================================================
// [清理] 以下为原存储库自带的过期硬编码 Hook 示例，因语法不兼容且不再需要，已进行安全注释
// =============================================================================
/*
 Il2CppObject * getFieldVal(Il2CppObject * obj, const char * name){
     auto field = il2cpp_class_get_field_from_name(obj->klass, name);
     return  il2cpp_field_get_value_object(field,obj);
}

static const MethodInfo * getData;
static const MethodInfo * hook1;
static const MethodInfo * hook2;

install_hook_name(func1,uint8_t,void * p){
    auto skillData = il2cpp_runtime_invoke(getData,p, nullptr, nullptr);
    auto level = getFieldVal(skillData,"level");
    int * val = static_cast<int32_t *>(il2cpp_object_unbox(level));
    if (*val > 6){
        return 1;
    }
    return 0;
}

install_hook_name(func2,uint8_t,void * p){
    return fake_func1(p);
}

install_hook_name(enemy,int32_t,Il2CppObject * p){
    return 0;
}
*/

void il2cpp_hook() {
    // 自动执行一次内存 Dump，我们的核心 Hook 现在在 hack.cpp 中通过 Dobby 单独处理
    il2cpp_dump();
}


void dump_class(Il2CppClass *klass) {
    // 这里保留核心的类名获取，原本针对旧游戏的硬编码判定已清除
    auto classNamespace = il2cpp_class_get_namespace(klass);
    auto className = il2cpp_class_get_name(klass);
    
    if (className != nullptr && classNamespace != nullptr) {
        // 如果以后想在日志里查看游戏都加载了哪些类，可以取消下面这行的注释：
        // LOGI("发现游戏类: %s.%s", classNamespace, className);
    }
}

void il2cpp_dump() {
    size_t size;
    auto domain = il2cpp_domain_get();
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    if (il2cpp_image_get_class) {
        LOGI("Version more than 2018.3");
        //使用il2cpp_image_get_class
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            auto classCount = il2cpp_image_get_class_count(image);
            for (int j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                dump_class(il2cpp_class_from_type(type));
            }
        }
    } else {
        LOGI("Version less than 2018.3");
        //使用反射
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (assemblyLoad && assemblyLoad->methodPointer) {
            LOGI("Assembly::Load: %p", assemblyLoad->methodPointer);
        } else {
            LOGI("miss Assembly::Load");
            return;
        }
        if (assemblyGetTypes && assemblyGetTypes->methodPointer) {
            LOGI("Assembly::GetTypes: %p", assemblyGetTypes->methodPointer);
        } else {
            LOGI("miss Assembly::GetTypes");
            return;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (int i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            auto image_name = il2cpp_image_get_name(image);
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(nullptr,
                                                                                        assemblyFileName,
                                                                                        nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            auto items = reflectionTypes->vector;
            for (int j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                dump_class(klass);
            }
        }
    }
}
