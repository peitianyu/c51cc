#!/usr/bin/env python3
"""
c89ify.py — 将 C99/C11 源文件批量转换为 C89 兼容风格。
主要处理：
  1. // 单行注释 → /* ... */
  2. for 循环内变量声明 → 提升到块首
  3. 函数/块内的中间变量声明 → 提升到块首
"""
import sys
import os
import re
import glob
import argparse
import tokenize
import io

# ───────────── 1. 单行注释转换 ─────────────


def convert_line_comments(src: str) -> str:
    """把 // ... 注释转换为 /* ... */，但不处理字符串/字符常量内的 //"""
    result = []
    i = 0
    n = len(src)
    while i < n:
        # 块注释直接透传
        if src[i : i + 2] == "/*":
            end = src.find("*/", i + 2)
            if end == -1:
                result.append(src[i:])
                break
            result.append(src[i : end + 2])
            i = end + 2
        # 字符串字面量
        elif src[i] == '"':
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                elif src[j] == '"':
                    j += 1
                    break
                else:
                    j += 1
            result.append(src[i:j])
            i = j
        # 字符常量
        elif src[i] == "'":
            j = i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                elif src[j] == "'":
                    j += 1
                    break
                else:
                    j += 1
            result.append(src[i:j])
            i = j
        # 单行注释
        elif src[i : i + 2] == "//":
            end = src.find("\n", i)
            comment_text = (
                src[i + 2 : end].rstrip() if end != -1 else src[i + 2 :].rstrip()
            )
            # 如果注释内容含 */ 则替换掉
            comment_text = comment_text.replace("*/", "* /")
            result.append("/*" + comment_text + " */")
            if end != -1:
                result.append("\n")
                i = end + 1
            else:
                break
        else:
            result.append(src[i])
            i += 1
    return "".join(result)


# ───────────── 2. for 循环内变量声明提升 ─────────────

C89_TYPES = (
    r"(?:unsigned\s+|signed\s+|long\s+|short\s+)*"
    r"(?:int|char|long|short|float|double|void|"
    r"unsigned|signed|struct\s+\w+|union\s+\w+|enum\s+\w+|\w+_t|\w+_T|\w+Ptr)"
)

FOR_DECL_RE = re.compile(
    r"for\s*\(\s*(" + C89_TYPES + r"\s*\*?\s*\w+(?:\s*=\s*[^,;)]+)?)(\s*[;,])",
    re.DOTALL,
)


def hoist_for_decl(src: str) -> str:
    """
    把 for (TYPE var = init; ...) 改为
    TYPE var = init; for (; ...);
    注意只处理简单的单变量声明（逗号分隔多声明暂不处理）
    """

    def replace_for(m):
        decl = m.group(1)  # e.g. "int i = 0"
        sep = m.group(2).strip()  # ; or ,
        if sep == ",":
            # 多变量声明，暂跳过
            return m.group(0)
        # 把 decl 提取出来，for( 里只保留空
        return decl + ";\n    for ("

    # 简单正则替换可能会有误判，此处用有限次迭代处理
    prev = None
    result = src
    for _ in range(10):
        prev = result
        result = FOR_DECL_RE.sub(replace_for, result)
        if result == prev:
            break
    return result


# ───────────── 3. 块内中间声明提升 ─────────────

STORAGE_SPECS = {"static", "extern", "auto", "register", "volatile", "const"}

BASE_TYPES = {
    "int",
    "char",
    "long",
    "short",
    "float",
    "double",
    "void",
    "unsigned",
    "signed",
    "struct",
    "union",
    "enum",
}

# 匹配一行开头的变量声明（C89 基本类型）
DECL_LINE_RE = re.compile(
    r"^(\s*)"  # 前导空白
    r"((?:(?:static|extern|auto|register|volatile|const|unsigned|signed|long|short)\s+)*"
    r"(?:int|char|long|short|float|double|void|unsigned|signed|"
    r"struct\s+\w+|union\s+\w+|enum\s+\w+|\w+_t)\s*"
    r"\**\s*\w+(?:\s*\[[^\]]*\])*"  # 变量名 + 可选数组下标
    r"(?:\s*,\s*\**\s*\w+(?:\s*\[[^\]]*\])*)*"  # 可选多变量
    r"(?:\s*=[^;{]+)?"  # 可选初始化
    r"\s*;)",  # 分号结尾
    re.MULTILINE,
)


def is_declaration_line(line: str) -> bool:
    """粗略判断一行是否是变量声明"""
    stripped = line.strip()
    if not stripped:
        return False
    # 以函数调用开头的赋值语句排除
    tokens = stripped.split()
    if not tokens:
        return False
    first = tokens[0].rstrip("*")
    # 排除明显不是类型的关键字
    if first in (
        "return",
        "if",
        "else",
        "for",
        "while",
        "do",
        "switch",
        "case",
        "break",
        "continue",
        "goto",
        "typedef",
        "sizeof",
    ):
        return False
    # 简单启发式：第一个词是已知类型或 *_t 形式
    if first in BASE_TYPES or first in STORAGE_SPECS:
        return True
    if re.match(r"\w+_[tT]$", first):
        return True
    # 如果有星号（指针）且下一个词看起来像标识符
    if stripped.startswith("*") or (len(tokens) > 1 and re.match(r"\w+", tokens[1])):
        pass
    return False


def move_decls_to_top(block_lines: list) -> list:
    """
    将一个 { } 块内的中间变量声明移到块首，
    简单策略：找到第一条非声明语句的位置，把之后的声明提到它之前。
    """
    # 找第一条真正的"语句"行（非声明、非空、非注释）
    first_stmt_idx = None
    for idx, line in enumerate(block_lines):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("/*") or stripped.startswith("//"):
            continue
        if is_declaration_line(line):
            continue
        first_stmt_idx = idx
        break

    if first_stmt_idx is None:
        return block_lines  # 全是声明，不需要移动

    # 找 first_stmt_idx 之后的声明行
    decls_after = []
    non_decls = []
    for line in block_lines[first_stmt_idx:]:
        stripped = line.strip()
        if not stripped:
            non_decls.append(line)
        elif is_declaration_line(line):
            decls_after.append(line)
        else:
            non_decls.append(line)

    if not decls_after:
        return block_lines

    # 重排：块首声明 + 提升的声明 + 语句
    return block_lines[:first_stmt_idx] + decls_after + non_decls


def process_blocks(src: str) -> str:
    """
    对源码中每个 { } 块进行声明提升。
    使用简单的括号计数方法定位块，不处理跨行宏等边缘情况。
    """
    # 逐字符扫描，找到每个块并处理其内容
    result = []
    i = 0
    n = len(src)

    def in_string_or_comment(pos):
        # 这里不做完整解析，仅依赖外层已转换为 /* */ 的注释
        return False

    depth = 0
    block_start = []  # stack of positions where { was found

    # 简单行级处理比字符级更稳健
    lines = src.splitlines(keepends=True)
    # 按块分层处理，仅处理深度1的块（函数体）
    # 更简单的策略：逐行扫，遇到函数体的 { 记录，遇到 } 触发提升
    return src  # 复杂情况跳过，改用更简单的逐文件处理


def process_file_simple(src: str) -> str:
    """
    简单的逐行处理：
    - 把 for (TYPE var ...) 中的声明提到 for 之前
    - 把块内首条非声明语句后面出现的声明移到块首（仅处理单层）
    实际上对于 C51 嵌入式测试文件，主要问题是 for 声明和 // 注释。
    """
    src = convert_line_comments(src)
    src = hoist_for_decl(src)
    src = hoist_mid_decls(src)
    return src


def hoist_mid_decls(src: str) -> str:
    """
    扫描函数体（以 { 开始、以配对 } 结束），将块内中间声明（第一条语句之后的声明）
    提升到块首第一条语句之前。
    只处理直接在函数体层（depth=1）的情况。
    """
    lines = src.splitlines(keepends=True)
    result = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.rstrip()

        # 检测函数体开始：行尾是 { 且不是 if/for/while/else/struct/enum 开头
        # 以及不是数组初始化 = {
        is_func_open = (
            stripped.endswith("{")
            and not re.match(
                r"\s*(if|else|for|while|do|switch|struct|union|enum|typedef)\b",
                stripped,
            )
            and "=" not in stripped
            and not stripped.strip().startswith("{")
        )

        if is_func_open:
            result.append(line)
            i += 1
            # 收集这个块的内容直到配对的 }
            block_lines = []
            depth = 1
            while i < n and depth > 0:
                l = lines[i]
                for ch in l:
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                block_lines.append(l)
                i += 1
            # 最后一行是配对的 }
            close_line = block_lines.pop() if block_lines else ""
            # 提升声明
            hoisted = move_decls_to_top(block_lines)
            result.extend(hoisted)
            result.append(close_line)
        else:
            result.append(line)
            i += 1

    return "".join(result)


def process_file(path: str, dry_run: bool = False) -> bool:
    """处理单个文件，返回是否有修改"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            src = f.read()
    except Exception as e:
        print(f"  [SKIP] {path}: {e}")
        return False

    new_src = process_file_simple(src)

    if new_src == src:
        return False

    if not dry_run:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(new_src)
    return True


def main():
    ap = argparse.ArgumentParser(description="Convert C99 test files to C89")
    ap.add_argument("paths", nargs="+", help="Files or glob patterns")
    ap.add_argument(
        "--dry-run", action="store_true", help="Show what would change without writing"
    )
    args = ap.parse_args()

    files = []
    for pat in args.paths:
        expanded = glob.glob(pat, recursive=True)
        if expanded:
            files.extend(expanded)
        elif os.path.isfile(pat):
            files.append(pat)

    changed = 0
    for f in sorted(set(files)):
        if process_file(f, dry_run=args.dry_run):
            changed += 1
            print(f"  [MODIFIED] {f}")
        else:
            print(f"  [OK]       {f}")

    print(f"\n总计: {len(files)} 文件, {changed} 个已修改")


if __name__ == "__main__":
    main()
