//
// Created by Perfare on 2020/7/4.
//

#ifndef ZYGISK_IL2CPPDUMPER_GAME_H
#define ZYGISK_IL2CPPDUMPER_GAME_H

#define GamePackageName1 "com.epidgames.trickcalrevive"
#define GamePackageName2 "com.epidgames.trickcalrevive"

// 翻译字典固定路径（应用专属外部目录，无需存储权限）。
// root 版：用户 adb push 到此；免 root 独立版：libhack.so 首启时把
// APK assets 内的 string_data.txt 释放到这里（已存在则不覆盖，方便热更字典）。
#define GameDictPath "/storage/emulated/0/Android/data/com.epidgames.trickcalrevive/files/string_data.txt"

#endif //ZYGISK_IL2CPPDUMPER_GAME_H
