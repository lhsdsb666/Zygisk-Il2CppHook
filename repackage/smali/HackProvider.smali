.class public Lcom/epidgames/trickcalrevive/hack/HackProvider;
.super Landroid/content/ContentProvider;

#
# [DIAG v7] 诊断构建：onCreate 只返回 true，故意不 System.loadLibrary("hack")。
# 整个包依旧重签/合并split/neutralize/split-strip/provider声明，但运行时
# 不加载 libhack、不安装任何 hook。
#   - 若仍弹 Error_1100 => 触发点是静态（重签名/DEX/新增文件），与运行时 hook 无关
#   - 若游戏正常 => 触发点是 libhack 加载或 Dobby inline hook
# 诊断后需把此文件还原为 loadLibrary 版本。
#

.method public constructor <init>()V
    .registers 1

    invoke-direct {p0}, Landroid/content/ContentProvider;-><init>()V

    return-void
.end method

.method public onCreate()Z
    .registers 3

    const-string v0, "chopperhl"
    const-string v1, "HackProvider DIAG: onCreate WITHOUT loadLibrary (no hooks running)"
    invoke-static {v0, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

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
