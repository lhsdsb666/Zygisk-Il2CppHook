#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
往 apktool 反编译后的 AndroidManifest.xml 注入 HackProvider 声明。
ContentProvider 由系统在 Application.onCreate 之前实例化，是免修改
原有类前提下最早的 System.loadLibrary 注入点。

用法: python3 inject_manifest.py <path-to-decoded-AndroidManifest.xml>
"""
import io
import sys

PROVIDER = (
    '    <provider android:name="com.epidgames.trickcalrevive.hack.HackProvider"\n'
    '        android:authorities="com.epidgames.trickcalrevive.hack"\n'
    '        android:exported="false" android:initOrder="2147483647" />\n'
)


def main(path):
    s = io.open(path, encoding='utf-8').read()
    if 'HackProvider' in s:
        print('[*] HackProvider already present, skip')
        return
    idx = s.rfind('</application>')
    if idx == -1:
        sys.exit('[!] ERROR: </application> not found in manifest')
    s = s[:idx] + PROVIDER + s[idx:]
    io.open(path, 'w', encoding='utf-8').write(s)
    print('[+] HackProvider injected into AndroidManifest.xml')


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'decoded/AndroidManifest.xml')
