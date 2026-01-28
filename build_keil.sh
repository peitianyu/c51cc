#!/bin/bash
# Keil C51 编译脚本 - 生成 HEX 文件

if [ $# -lt 1 ]; then
    echo "用法: $0 <源文件.c>"
    exit 1
fi

SRC_FILE=$1
BASE_NAME=${SRC_FILE%.c}
OBJ_FILE=${BASE_NAME}.OBJ
HEX_FILE=${BASE_NAME}.HEX

echo "=== 编译 C 文件 ==="
C51.exe $SRC_FILE

echo "=== 链接目标文件 ==="
BL51.exe $OBJ_FILE TO ${BASE_NAME}.ABS

echo "=== 生成 HEX 文件 ==="
OH51.exe ${BASE_NAME}.ABS

echo "=== 完成 ==="
echo "生成的 HEX 文件: $HEX_FILE"

rm $OBJ_FILE ${BASE_NAME}.ABS ${BASE_NAME}.M51