# Keil C51 编译脚本 - 生成 HEX 文件
# 改写说明: 增加可用性检测、错误处理、路径处理和更友好的输出

set -o pipefail

usage() {
    echo "用法: $0 <源文件.c>"
    exit 1
}

cmd_exists() {
    command -v "$1" >/dev/null 2>&1
}

if [ $# -lt 1 ]; then
    usage
fi

SRC_FILE="$1"
if [ ! -f "$SRC_FILE" ]; then
    echo "错误: 源文件不存在: $SRC_FILE"
    exit 2
fi

BASE_NAME="${SRC_FILE%.c}"
OBJ_FILE="${BASE_NAME}.OBJ"
ABS_FILE="${BASE_NAME}.ABS"
HEX_FILE="${BASE_NAME}.HEX"

echo "=== 检查 Keil 工具链可用性 ==="
for tool in C51.exe BL51.exe OH51.exe; do
    if ! cmd_exists "$tool"; then
        echo "未找到 $tool - 请确保 Keil 命令行工具在 PATH 中，或从 Keil 的安装目录运行本脚本。"
        exit 3
    fi
done

run_or_fail() {
    echo "++ $*"
    "$@"
    rc=$?
    if [ $rc -ne 0 ]; then
        echo "错误: 命令失败 (退出码 $rc): $*"
        exit $rc
    fi
}

echo "=== 编译 C 文件 ==="
run_or_fail C51.exe "$SRC_FILE"

echo "=== 链接目标文件 ==="
# 保持原有 BL51 调用样式（如果需要修改链接参数请在这里调整）
run_or_fail BL51.exe "$OBJ_FILE" TO "$ABS_FILE"

echo "=== 生成 HEX 文件 ==="
run_or_fail OH51.exe "$ABS_FILE"

if [ -f "$HEX_FILE" ]; then
    echo "=== 完成 ==="
    echo "生成的 HEX 文件: $HEX_FILE"
else
    echo "警告: 未找到生成的 HEX 文件: $HEX_FILE"
fi

echo "清理中（可根据需要注释掉）..."
rm -f "$OBJ_FILE" "$ABS_FILE" "${BASE_NAME}.M51"