# C51 汇编中的 PHI 节点处理

## 问题背景

PHI 节点是 SSA 形式的特性，表示从不同控制流路径汇聚的值。例如：

```ssa
block12:
  jmp b14

block13:
  jmp b14

block14:
  v56 = phi [v54, b12], [v55, b13]
  ret v56
```

这表示：
- 如果来自 block12，v56 = v54
- 如果来自 block13，v56 = v56

## 处理方法

### 方法1：在前驱块末尾插入 MOV（推荐）

在每个前驱块的末尾（跳转前），插入 MOV 指令将值复制到 PHI 目标：

```asm
; block12
    ...
    MOV R5, R3    ; v54 -> v56
    LJMP block14

; block13
    ...
    MOV R5, R4    ; v55 -> v56
    LJMP block14

; block14
    ; 现在 R5 就是 v56
    MOV A, R5
    RET
```

### 方法2：关键边分割 (Critical Edge Splitting)

如果存在"关键边"（从有多后继的块到有多前驱的块），需要插入新块：

```ssa
; 原始
block1:          ; 有多个后继
  br cond, block2, block3

block2:          ; 有多个前驱
  v1 = phi [a, block1], [b, block4]
```

分割后：
```ssa
block1:
  br cond, block1_to_2, block3

block1_to_2:     ; 新插入的块
  mov tmp, a
  jmp block2

block4_to_2:     ; 新插入的块
  mov tmp, b
  jmp block2

block2:
  v1 = tmp       ; 简化的PHI
```

## C51 实现策略

### 当前实现
目前的 `c51gen.c` 只是打印注释，没有实际处理：
```c
case IROP_PHI:
    emit_comment(gen, "PHI: v%d", inst->dest);
    break;
```

### 完整实现步骤

1. **遍历所有 PHI 节点**
   ```c
   for (每个基本块) {
       for (每个 PHI 节点) {
           确定 PHI 目标位置（寄存器或内存）
       }
   }
   ```

2. **在前驱块插入 MOV**
   ```c
   for (每个 PHI 参数 [val, pred_block]) {
       在 pred_block 的末尾（跳转指令前）插入：
       MOV phi_location, val_location
   }
   ```

3. **处理寄存器分配**
   - PHI 目标应该分配固定的寄存器/内存位置
   - 所有前驱块都写入同一位置

## 示例：完整的 PHI 处理

### SSA IR
```
block10:
  ret a           ; v54 = a

block11:
  ret b           ; v55 = b

block12:
  v56 = phi [v54, b10], [v55, b11]
  ret v56
```

### 生成的 C51 汇编
```asm
; block10
    MOV A, R6       ; a 已经在 R6
    MOV R7, A       ; v54 -> PHI目标 R7
    LJMP block12

; block11
    MOV A, R5       ; b 已经在 R5
    MOV R7, A       ; v55 -> PHI目标 R7
    LJMP block12

; block12
    MOV A, R7       ; 使用 PHI 值
    RET
```

## 优化考虑

### 1. 寄存器 coalescing
如果 PHI 的源和目标可以分配到同一寄存器，可以消除 MOV：
```
v2 = phi [v1, block1]
; 如果 v1 和 v2 可以共享寄存器，就不需要 MOV
```

### 2. 并行复制 (Parallel Copy)
当多个 PHI 同时存在时，需要考虑依赖：
```
v3 = phi [v1, block1]
v4 = phi [v2, block1]
```
可能需要临时寄存器来避免覆盖。

## 参考实现代码

```c
// 收集块的所有 PHI 目标
typedef struct PhiCopy {
    ValueName src;      // 源值
    ValueName dest;     // PHI 目标
    Block *pred;        // 来自哪个前驱
} PhiCopy;

static void emit_phi_copies(C51Gen *gen, Block *blk) {
    // 遍历 PHI 节点
    for (Iter jt = list_iter(blk->phis); !iter_end(jt);) {
        Instr *phi = iter_next(&jt);
        
        // 获取 PHI 目标位置
        char dest_loc[32];
        get_location(gen, phi->dest, dest_loc, sizeof(dest_loc));
        
        // 为每个参数在前驱块插入 MOV
        for (int i = 0; i < phi->args->len; i++) {
            ValueName *src = list_get(phi->args, i);
            char *pred_label = list_get(phi->labels, i);
            
            // 找到对应的前驱块
            Block *pred = find_block_by_label(gen, pred_label);
            
            // 在 pred 的跳转指令前插入 MOV
            insert_mov_before_jump(gen, pred, *src, phi->dest);
        }
    }
}
```

## 关键问题

1. **何时处理 PHI？**
   - 在寄存器分配之后（知道具体位置）
   - 在生成代码之前或期间

2. **如何处理内存溢出？**
   - PHI 目标可能在栈上
   - 使用 MOV 直接操作内存

3. **循环中的 PHI？**
   - 需要特殊处理反向边
   - 确保循环头正确初始化
