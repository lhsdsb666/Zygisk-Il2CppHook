//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_HACK_H
#define ZYGISK_IL2CPPDUMPER_HACK_H

#include <stddef.h>

void hack_prepare(const char *game_data_dir, void *data, size_t length);

// 免 root 独立注入版使用（定义在 hack.cpp）：
//  hack_start          —— 翻译主流程（内部自行轮询等待 libil2cpp.so，线程安全）
//  hook_exit_functions —— 拦截 exit/_exit/kill/tgkill 防完整性检测自杀
void hack_start(const char *game_data_dir);
void hook_exit_functions();

#endif //ZYGISK_IL2CPPDUMPER_HACK_H
