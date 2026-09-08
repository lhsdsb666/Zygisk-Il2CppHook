.class public Lcom/epidgames/trickcalrevive/hack/HackProvider;
.super Landroid/content/ContentProvider;

#
# 免 root 汉化注入点：ContentProvider 在 Application.onCreate 之前由系统
# 实例化（attachBaseContext 之后、Presto Loader 初始化之前），是免修改
# 原有类前提下最早的可控执行点。onCreate 里 System.loadLibrary("hack")
# 加载 libhack.so，其 JNI_OnLoad 会立即安装 exit blocker 并启动翻译线程。
#
# 任何异常都吞掉并返回 true：加载失败也绝不能拖垮游戏启动。
#

.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V

    return-void
.end method

.method public onCreate()Z
    .registers 4

    :try_start
    const-string v1, "chopperhl"
    const-string v2, "HackProvider onCreate: loading libhack.so ..."
    invoke-static {v1, v2}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    const-string v0, "hack"
    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    const-string v2, "HackProvider onCreate: libhack.so loaded OK"
    invoke-static {v1, v2}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I
    :try_end
    .catch Ljava/lang/Throwable; {:try_start .. :try_end} :catch_0

    goto :goto_0

    :catch_0
    move-exception v0

    invoke-virtual {v0}, Ljava/lang/Throwable;->printStackTrace()V

    const-string v1, "chopperhl"
    const-string v2, "HackProvider onCreate: loadLibrary FAILED (game continues anyway)"
    invoke-static {v1, v2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    :goto_0
    const/4 v0, 0x1

    return v0
.end method

.method public query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    .registers 6

    const/4 v0, 0x0

    return-object v0
.end method

.method public getType(Landroid/net/Uri;)Ljava/lang/String;
    .registers 2

    const/4 v0, 0x0

    return-object v0
.end method

.method public insert(Landroid/net/Uri;Landroid/content/ContentValues;)Landroid/net/Uri;
    .registers 3

    const/4 v0, 0x0

    return-object v0
.end method

.method public delete(Landroid/net/Uri;Ljava/lang/String;[Ljava/lang/String;)I
    .registers 4

    const/4 v0, 0x0

    return v0
.end method

.method public update(Landroid/net/Uri;Landroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/String;)I
    .registers 5

    const/4 v0, 0x0

    return v0
.end method
