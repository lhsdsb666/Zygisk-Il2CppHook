#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apktool 反编译后的 AndroidManifest.xml 改造（单 APK 整合包必须）：
  1. 注入 HackProvider 声明（ContentProvider，Application 启动前 loadLibrary）
  2. 剥除 Google Play 分包(split APK)声明 —— 原版是 base+split 分发，
     base Manifest 带 requiredSplitTypes/isSplitRequired + vending.splits
     meta-data；合并成单包后若保留，PackageManager 安装时报
     INSTALL_FAILED_MISSING_SPLIT。

用法: python3 inject_manifest.py <path-to-decoded-AndroidManifest.xml>
"""
import io
import re
import sys

PROVIDER = (
    '    <provider android:name="com.epidgames.trickcalrevive.hack.HackProvider"\n'
    '        android:authorities="com.epidgames.trickcalrevive.hack"\n'
    '        android:exported="false" android:initOrder="2147483647" />\n'
)

# 需要整元素删除的 Play 分包 meta-data
SPLIT_METADATA = (
    "com.android.vending.splits.required",
    "com.android.vending.splits",
)

# 需要删除的属性（出现在任何标签上都删）
SPLIT_ATTRS = (
    "android:requiredSplitTypes",
    "android:isSplitRequired",
    "android:splitTypes",
)


def strip_split_metadata(s):
    for name in SPLIT_METADATA:
        # apktool 输出里每个 <meta-data .../> 通常在同一行；DOTALL 兜底跨行
        pat = re.compile(
            r"\s*<meta-data\b[^>]*?android:name=\"" + re.escape(name) +
            r"\"[^>]*/>", re.S)
        s, n = pat.subn("", s)
        print("[*] removed <meta-data %s>: %d occurrence(s)" % (name, n))
    return s


def strip_split_attrs(s):
    for attr in SPLIT_ATTRS:
        pat = re.compile(r"\s*" + re.escape(attr) + r"=\"[^\"]*\"")
        s, n = pat.subn("", s)
        print("[*] removed attribute %s: %d occurrence(s)" % (attr, n))
    return s


def inject_provider(s):
    if "HackProvider" in s:
        print("[*] HackProvider already present, skip")
        return s
    idx = s.rfind("</application>")
    if idx == -1:
        sys.exit("[!] ERROR: </application> not found in manifest")
    s = s[:idx] + PROVIDER + s[idx:]
    print("[+] HackProvider injected into AndroidManifest.xml")
    return s


def main(path):
    s = io.open(path, encoding="utf-8").read()
    s = strip_split_metadata(s)
    s = strip_split_attrs(s)
    s = inject_provider(s)
    io.open(path, "w", encoding="utf-8").write(s)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "decoded/AndroidManifest.xml")
