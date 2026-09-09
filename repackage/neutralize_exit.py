#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中和 smali 中所有 Java 层"进程自杀"调用点。

背景：
  重签名整合包启动 8 秒左右，反篡改 SDK（Presto/ATG 等）在 Java 层检测到
  APK 签名/完整性异常后调用 System.exit(0) 静默退出（logcat 只有
  "System.exit called, status: 0"，没有任何崩溃墓碑）。
  MuMu 这类 x86_64 模拟器上，ART 虚拟机本身是 x86_64 原生代码，走系统
  libc；而 libhack.so 是 arm64 翻译执行，Dobby 只能钩到翻译层 libc。
  因此 Java 侧的 exit/halt/killProcess native hook 拦不住，必须在
  smali 层直接移除调用点：方法随后继续执行并正常返回，游戏不退出。

  处理的调用（均为 void 返回，删除指令不影响寄存器数据流）：
    invoke-static  {..}, Ljava/lang/System;->exit(I)V
    invoke-virtual {..}, Ljava/lang/Runtime;->exit(I)V
    invoke-virtual {..}, Ldalvik/system/VMRuntime;->halt(I)V
    invoke-static  {..}, Landroid/os/Process;->killProcess(I)V

用法: python3 neutralize_exit.py <apktool 反编译目录>
"""
import os, re, sys

# smali 指令 -> 匹配正则（方法名/描述符精确匹配）
PATTERNS = [
    ("System.exit",        re.compile(r'^\s*invoke-static\s+\{[^}]*\},\s*Ljava/lang/System;->exit\(I\)V\s*$')),
    ("Runtime.exit",       re.compile(r'^\s*invoke-virtual\s+\{[^}]*\},\s*Ljava/lang/Runtime;->exit\(I\)V\s*$')),
    ("VMRuntime.halt",     re.compile(r'^\s*invoke-virtual\s+\{[^}]*\},\s*Ldalvik/system/VMRuntime;->halt\(I\)V\s*$')),
    ("Process.killProcess",re.compile(r'^\s*invoke-static\s+\{[^}]*\},\s*Landroid/os/Process;->killProcess\(I\)V\s*$')),
]

def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "decoded"
    total = {name: 0 for name, _ in PATTERNS}
    files_changed = 0
    for dp, dn, fn in os.walk(root):
        rel = os.path.relpath(dp, root).replace("\\", "/")
        # apktool 反编译产物里 smali 全部位于 smali/ 或 smali_classesN/ 下
        if rel != "." and not (rel == "smali" or rel.startswith("smali/")
                               or re.match(r"smali_classes\d+(?:/|$)", rel)):
            continue
        for f in fn:
            if not f.endswith(".smali"):
                continue
            path = os.path.join(dp, f)
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
            out = []
            changed = 0
            for line in lines:
                hit = None
                for name, rx in PATTERNS:
                    if rx.match(line):
                        hit = name
                        break
                if hit:
                    total[hit] += 1
                    changed += 1
                    indent = line[:len(line) - len(line.lstrip())]
                    out.append(f"{indent}# [neutralized] removed {hit}() anti-tamper self-kill\n")
                else:
                    out.append(line)
            if changed:
                files_changed += 1
                with open(path, "w", encoding="utf-8") as fh:
                    fh.writelines(out)
                print(f"  {path.replace(root + os.sep, '')}: 中和 {changed} 处")
    print("=" * 60)
    for name, cnt in total.items():
        print(f"  {name:<22} {cnt} 处")
    print(f"  共修改 {files_changed} 个 smali 文件")
    if files_changed == 0:
        print("[warn] 未发现任何 exit/halt/killProcess 调用点（请确认反编译目录正确）")

if __name__ == "__main__":
    main()
