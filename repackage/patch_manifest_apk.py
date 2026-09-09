#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
apktool 重打包后的确定性补丁：从最终 APK 的二进制 AndroidManifest.xml 中
"清除" Google Play 分包（split APK）声明。

背景：
  游戏原版是 Play split APK（base + split_config.arm64_v8a）。我们把 split
  的 so 合并进单包，但 Manifest 里仍带着：
    - <manifest android:requiredSplitTypes=... android:splitTypes=...
                android:isSplitRequired=true>
    - <meta-data android:name="com.android.vending.splits.required">
    - <meta-data android:name="com.android.vending.splits" android:resource=...>
  PackageManager 据此抛出 INSTALL_FAILED_MISSING_SPLIT。
  apktool 解包/回编译时这些声明会"复活"（aapt 甚至会自己补 isSplitRequired），
  文本层正则去不干净。二进制 AXML 的属性/meta-data 全部靠"名字"解析，
  这里直接在字符串池里把目标字符串原地改写为等长的 'x'——长度/偏移一律不变，
  包管理器按名查表查不到，这些属性和 meta-data 即被忽略。

用法: python3 patch_manifest_apk.py <in.apk> <out.apk>
"""
import sys, zipfile

# 注意顺序无关：字符串池中每个条目独立精确匹配
TARGETS = (
    b"com.android.vending.splits.required",
    b"com.android.vending.splits",
    b"requiredSplitTypes",
    b"isSplitRequired",
    b"splitTypes",
)

def patch_axml(data: bytes):
    assert data[:4] == b'\x03\x00\x08\x00', "not a binary AXML file"
    sp = 8  # 第一个 chunk 即字符串池（紧随 8 字节文件头）
    ctype = int.from_bytes(data[sp:sp+2], 'little')
    assert ctype == 0x0001, "first chunk is not string pool"
    scount = int.from_bytes(data[sp+8:sp+12], 'little')
    flags  = int.from_bytes(data[sp+16:sp+20], 'little')
    sstart = int.from_bytes(data[sp+20:sp+24], 'little')
    utf8 = bool(flags & 0x100)
    offs = [int.from_bytes(data[sp+0x1c+4*i:sp+0x1c+4*i+4], 'little')
            for i in range(scount)]
    base = sp + sstart
    buf = bytearray(data)
    found = {}
    for off in offs:
        p = base + off
        q = p
        if utf8:
            # [u8 字符数(可能2字节)] [u8 字节数(可能2字节)] [bytes] [NUL]
            n = buf[q]; q += 1
            if n & 0x80: q += 1
            bl = buf[q]; q += 1
            if bl & 0x80:
                bl = ((bl & 0x7f) << 8) | buf[q]; q += 1
            s = bytes(buf[q:q+bl])
            if s in TARGETS:
                buf[q:q+bl] = b'x' * bl
                found[s.decode()] = found.get(s.decode(), 0) + 1
        else:
            n = int.from_bytes(buf[q:q+2], 'little'); q += 2
            if n & 0x8000:
                n = ((n & 0x7fff) << 16) | int.from_bytes(buf[q:q+2], 'little')
                q += 2
            bl = n * 2
            s = bytes(buf[q:q+bl]).decode('utf-16-le')
            if s in (t.decode('ascii') for t in TARGETS):
                # 每两字节改成 0x78 0x00（'x' 的 UTF-16LE），等长
                for i in range(n):
                    buf[q+2*i]   = 0x78
                    buf[q+2*i+1] = 0x00
                found[s] = found.get(s, 0) + 1
    return bytes(buf), found

def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(2)
    in_apk, out_apk = sys.argv[1], sys.argv[2]
    zin = zipfile.ZipFile(in_apk, 'r')
    zout = zipfile.ZipFile(out_apk, 'w')
    total = {}
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == 'AndroidManifest.xml':
            data, found = patch_axml(data)
            for k, v in found.items():
                total[k] = total.get(k, 0) + v
        # 保持原压缩方式与对齐属性
        zi = zipfile.ZipInfo(item.filename, date_time=item.date_time)
        zi.compress_type = item.compress_type
        zi.external_attr = item.external_attr
        zi.internal_attr = item.internal_attr
        zi.create_system = item.create_system
        zout.writestr(zi, data)
    zout.close(); zin.close()

    print("[patch_manifest] split 声明字符串池改写结果:")
    for t in TARGETS:
        print("   %-38s %d 处" % (t.decode(), total.get(t.decode(), 0)))
    if not total:
        print("[patch_manifest] 未发现目标字符串（可能已干净）。")
    # 校验：输出文件里一个目标字符串都不该再出现（UTF-8 / UTF-16LE 两种形式）
    zchk = zipfile.ZipFile(out_apk)
    m = zchk.read('AndroidManifest.xml')
    leftover = []
    for t in TARGETS:
        u8 = t
        u16 = t.decode('ascii').encode('utf-16-le')
        if u8 in m or u16 in m:
            leftover.append(t.decode())
    if leftover:
        print("[patch_manifest][FATAL] 仍有残留:", leftover)
        sys.exit(1)
    print("[patch_manifest] OK: AndroidManifest.xml 中 split 声明已全部失效。")

if __name__ == '__main__':
    main()
