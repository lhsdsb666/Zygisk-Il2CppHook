//
// Created by Perfare on 2020/7/4.
// 最终修正版：使用无参 LoadAllAssets 提取字库，完美避开崩溃
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

// ==================== 数据结构 ====================
struct MyIl2CppString {
    void* klass;
    void* monitor;
    int32_t length;
    char16_t chars[0]; 
};

struct MyIl2CppArray {
    void* klass;
    void* monitor;
    void* bounds;
    intmax_t max_length; 
    void* vector[0];     
};

typedef MyIl2CppString* (*il2cpp_string_new_ptr)(const char* text);
static il2cpp_string_new_ptr il2cpp_string_new = nullptr;
static void* china_font_asset_ptr = nullptr;

typedef void* (*il2cpp_object_get_class_fn)(void* obj);
typedef void* (*il2cpp_class_get_field_from_name_fn)(void* klass, const char* name);
typedef void (*il2cpp_field_set_value_fn)(void* obj, void* field, void** value);
typedef void (*il2cpp_class_get_parent_fn)(void* klass); 

static il2cpp_object_get_class_fn il2cpp_object_get_class = nullptr;
static il2cpp_class_get_field_from_name_fn il2cpp_class_get_field_from_name = nullptr;
static il2cpp_field_set_value_fn il2cpp_field_set_value = nullptr;
static il2cpp_class_get_parent_fn il2cpp_class_get_parent = nullptr; 

// ==================== 核心 API ====================
typedef void* (*AssetBundle_LoadFromFile_t)(MyIl2CppString* path);
typedef MyIl2CppArray* (*AssetBundle_LoadAllAssets_t)(void* __this);

static AssetBundle_LoadFromFile_t Unity_LoadFromFile = nullptr;
static AssetBundle_LoadAllAssets_t Unity_LoadAllAssets = nullptr;

static const std::unordered_map<std::string, std::string> translation_dict = {
    {"상점", "商店"}, {"친구", "好友"}, {"이벤트 팝업", "活动"},
    {"레벨 패스", "等级通行证"}, {"BETA", "测试版"}
};

// 工具函数
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
            utf8 += (char)(0xc0 | (cp >> 6)); utf8 += (char)(0x80 | (cp & 0x3f));
        } else if (cp <= 0xffff) {
            utf8 += (char)(0xe0 | (cp >> 12)); utf8 += (char)(0x80 | ((cp >> 6) & 0x3f)); utf8 += (char)(0x80 | (cp & 0x3f));
        }
    }
    return utf8;
}

std::string get_module_path_and_base(const char* module_name, uintptr_t& out_base) {
    out_base = 0; char line[512];
    FILE* fp = fopen("/proc/self/maps", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            if (strstr(line, module_name)) {
                if (out_base == 0) out_base = strtoul(line, nullptr, 16);
                char* path_start = strchr(line, '/');
                if (path_start) {
                    std::string path(path_start);
                    while (!path.empty() && (path.back() < 33)) path.pop_back();
                    fclose(fp); return path;
                }
            }
        }
        fclose(fp);
    }
    return "";
}

// 核心加载
static bool g_font_loaded = false;
void load_chinese_font_asset(uintptr_t il2cpp_base) {
    if (g_font_loaded) return;
    Unity_LoadFromFile = (AssetBundle_LoadFromFile_t)(il2cpp_base + 0xb64fe38);
    // 修正后的地址：0xb65077c
    Unity_LoadAllAssets = (AssetBundle_LoadAllAssets_t)(il2cpp_base + 0xb65077c); 

    const char* path = "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/zh-hans";
    void* font_bundle = Unity_LoadFromFile(il2cpp_string_new(path));

    if (font_bundle) {
        MyIl2CppArray* asset_array = Unity_LoadAllAssets(font_bundle);
        if (asset_array && asset_array->max_length > 0) {
            china_font_asset_ptr = asset_array->vector[0];
            LOGI("[HACK_FONT] SUCCESS: Font loaded from index 0!");
        }
    }
    g_font_loaded = true;
}

// 拦截逻辑
void* find_field_in_hierarchy(void* klass, const char* field_name) {
    while (klass) {
        void* field = il2cpp_class_get_field_from_name(klass, field_name);
        if (field) return field;
        klass = il2cpp_class_get_parent(klass);
    }
    return nullptr;
}

static void (*old_set_text)(void* __this, MyIl2CppString* il2cpp_string) = nullptr;
void my_set_text(void* __this, MyIl2CppString* il2cpp_string) {
    if (china_font_asset_ptr && __this && il2cpp_object_get_class) {
        void* text_klass = il2cpp_object_get_class(__this);
        void* font_field = find_field_in_hierarchy(text_klass, "m_fontAsset");
        if (font_field && il2cpp_field_set_value) {
            il2cpp_field_set_value(__this, font_field, &china_font_asset_ptr);
        }
    }
    old_set_text(__this, il2cpp_string);
}

void hack_start(const char *game_data_dir) {
    uintptr_t il2cpp_base = 0;
    for (int i = 0; i < 300; i++) {
        std::string path = get_module_path_and_base("libil2cpp.so", il2cpp_base);
        if (il2cpp_base != 0) {
            void *handle = dlopen(path.c_str(), RTLD_LAZY);
            il2cpp_string_new = (il2cpp_string_new_ptr)dlsym(handle, "il2cpp_string_new");
            il2cpp_object_get_class = (il2cpp_object_get_class_fn)dlsym(handle, "il2cpp_object_get_class");
            il2cpp_class_get_field_from_name = (il2cpp_class_get_field_from_name_fn)dlsym(handle, "il2cpp_class_get_field_from_name");
            il2cpp_field_set_value = (il2cpp_field_set_value_fn)dlsym(handle, "il2cpp_field_set_value");
            il2cpp_class_get_parent = (il2cpp_class_get_parent_fn)dlsym(handle, "il2cpp_class_get_parent");
            
            DobbyHook((void*)(il2cpp_base + 0xb5b099c), (void*)my_set_text, (void**)&old_set_text);
            load_chinese_font_asset(il2cpp_base);
            break;
        }
        sleep(1);
    }
}
