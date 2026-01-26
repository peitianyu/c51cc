from typing import List, Any, Dict, Set, Tuple, Optional

# -------------------- AST 定义 --------------------
class ASTNode: pass

class BinaryOp(ASTNode):
    def __init__(self, op: str, left: ASTNode, right: ASTNode):
        self.op, self.left, self.right = op, left, right

class Assignment(ASTNode):
    def __init__(self, var: str, expr: ASTNode):
        self.var, self.expr = var, expr

class Variable(ASTNode):
    def __init__(self, name: str): 
        self.name = name

class Constant(ASTNode):
    def __init__(self, value: Any): 
        self.value = value

class If(ASTNode):
    def __init__(self, cond, then_stmt, else_stmt=None):
        self.condition, self.then_stmt, self.else_stmt = cond, then_stmt, else_stmt

class While(ASTNode):
    def __init__(self, condition, body): 
        self.condition, self.body = condition, body

class Block(ASTNode):
    def __init__(self, statements: List[ASTNode]): 
        self.statements = statements

# -------------------- SSA 基础 --------------------
class Value:
    _counter = 0
    
    def __init__(self):
        self.id = Value._counter
        Value._counter += 1
        self.users: Set['Instruction'] = set()
    
    def add_user(self, user: 'Instruction'):  
        self.users.add(user)
    
    def __repr__(self):
        return f"var{self.id}"

class Instruction(Value):
    def __init__(self, opcode: str):
        super().__init__()
        self.opcode = opcode
        self.operands: List[Value] = []
        self.block: Optional['BasicBlock'] = None
    
    def add_user(self, user: 'Instruction'):
        self.users.add(user)
    
    def replace_operand(self, old_val: Value, new_val: Value):
        for i, op in enumerate(self.operands):
            if op == old_val:
                self.operands[i] = new_val
                new_val.add_user(self)

class PhiInstruction(Instruction):
    def __init__(self, var: str):
        super().__init__("phi")
        self.variable = var
        self.operands: List[Tuple['BasicBlock', Value]] = []
    
    def add_operand(self, block: 'BasicBlock', value: Value):
        self.operands.append((block, value))
        value.add_user(self)

class JumpInstruction(Instruction):
    def __init__(self, target: 'BasicBlock'): 
        super().__init__("jmp")
        self.target_block = target

class BranchInstruction(Instruction):
    def __init__(self, cond: Value, true_blk: 'BasicBlock', false_blk: 'BasicBlock'):
        super().__init__("br")
        self.condition = cond
        self.true_block = true_blk
        self.false_block = false_blk

class ConstantValue(Value):
    _const_registry: Dict[Any, 'ConstantValue'] = {}
    
    def __new__(cls, value: Any):
        if value in cls._const_registry:
            return cls._const_registry[value]
        instance = super().__new__(cls)
        cls._const_registry[value] = instance
        return instance
    
    def __init__(self, value: Any):
        if hasattr(self, '_initialized'):
            return
        super().__init__()
        self.constant_value = value
        self._initialized = True
    
    def __repr__(self):
        return f"var{self.id}"

class BasicBlock:
    _counter = 0
    
    __slots__ = ('id', 'name', 'preds', 'instructions', 'phi_instructions', 
                 'var_defs', 'sealed', 'incomplete_phis', 'constructor')
    
    def __init__(self):
        self.id = BasicBlock._counter
        BasicBlock._counter += 1
        self.name = f"block{self.id}"
        self.preds: List['BasicBlock'] = []
        self.instructions: List[Instruction] = []
        self.phi_instructions: List[PhiInstruction] = []
        self.var_defs: Dict[str, Value] = {}
        self.sealed = False
        self.incomplete_phis: List[Tuple[str, PhiInstruction]] = []
        self.constructor: Optional['BraunSSAConstructor'] = None
    
    def add_pred(self, pred: 'BasicBlock'):
        if pred not in self.preds:
            self.preds.append(pred)
    
    def add_instruction(self, inst: Instruction):
        inst.block = self
        if isinstance(inst, PhiInstruction):
            self.phi_instructions.append(inst)
        else:
            self.instructions.append(inst)
    
    def __repr__(self):
        return f"block{self.id}"

# -------------------- BraunSSAConstructor --------------------
class BraunSSAConstructor:
    def __init__(self):
        self.blocks: Dict[int, BasicBlock] = {}
        self.current_block_id = 0
    
    def create_block(self) -> BasicBlock:
        blk = BasicBlock()
        blk.constructor = self
        self.blocks[blk.id] = blk
        return blk
    
    def create_instruction(self, op: str, ops: List[Value]) -> Instruction:
        inst = Instruction(op)
        inst.operands = ops
        for o in ops:
            o.add_user(inst)
        return inst
    
    def create_jump(self, tgt: BasicBlock) -> JumpInstruction:
        return JumpInstruction(tgt)
    
    def create_branch(self, cond: Value, t: BasicBlock, f: BasicBlock) -> BranchInstruction:
        return BranchInstruction(cond, t, f)
    
    def create_constant(self, v: Any) -> ConstantValue:
        return ConstantValue(v)
    
    def write_var(self, var: str, blk: BasicBlock, val: Value) -> Value:
        blk.var_defs[var] = val
        return val
    
    def read_var(self, var: str, blk: BasicBlock) -> Value:
        if var in blk.var_defs:
            return blk.var_defs[var]
        return self._read_var_recursive(var, blk)
    
    def _read_var_recursive(self, var: str, blk: BasicBlock) -> Value:
        if not blk.sealed:
            phi = self._create_phi(var, blk)
            blk.incomplete_phis.append((var, phi))
            blk.var_defs[var] = phi
            blk.add_instruction(phi)
            return phi
        elif len(blk.preds) == 1:
            return self.read_var(var, blk.preds[0])
        else:
            phi = self._create_phi(var, blk)
            blk.var_defs[var] = phi
            blk.add_instruction(phi)
            return self._add_phi_operands(var, phi)
    
    def _create_phi(self, var: str, blk: BasicBlock) -> PhiInstruction:
        phi = PhiInstruction(var)
        phi.block = blk
        return phi
    
    def _add_phi_operands(self, var: str, phi: PhiInstruction) -> Value:
        for pred in phi.block.preds:
            val = self.read_var(var, pred)
            phi.add_operand(pred, val)
        return self._try_remove_trivial_phi(phi)
    
    def _try_remove_trivial_phi(self, phi: PhiInstruction) -> Value:
        unique = set()
        for blk, val in phi.operands:
            if val != phi:
                unique.add(val)
        
        if len(unique) == 1:
            same = unique.pop()
            for u in list(phi.users):
                u.replace_operand(phi, same)
            if phi.block and phi in phi.block.phi_instructions:
                phi.block.phi_instructions.remove(phi)
            if phi.block and phi.block.var_defs.get(phi.variable) == phi:
                phi.block.var_defs[phi.variable] = same
            return same
        elif len(unique) == 0:
            undef = self.create_constant(None)
            for u in list(phi.users):
                u.replace_operand(phi, undef)
            if phi.block and phi in phi.block.phi_instructions:
                phi.block.phi_instructions.remove(phi)
            if phi.block and phi.block.var_defs.get(phi.variable) == phi:
                phi.block.var_defs[phi.variable] = undef
            return undef
        return phi
    
    def seal_block(self, blk: BasicBlock):
        blk.sealed = True
        for var, phi in blk.incomplete_phis:
            if not phi.operands:
                for pred in blk.preds:
                    phi.add_operand(pred, self.read_var(var, pred))
                result = self._try_remove_trivial_phi(phi)
                if result != phi:
                    blk.var_defs[var] = result

# -------------------- AST→SSA 转换器 --------------------
class ASTToSSAConverter:
    def __init__(self):
        self.constructor = BraunSSAConstructor()
        self.current_block: Optional[BasicBlock] = None
    
    def convert(self, ast: ASTNode) -> BraunSSAConstructor:
        entry = self.constructor.create_block()
        self.current_block = entry
        self._convert_node(ast)
        
        for blk in self.constructor.blocks.values():
            if not blk.sealed:
                self.constructor.seal_block(blk)
        return self.constructor
    
    def _convert_node(self, node: ASTNode) -> Optional[Value]:
        if isinstance(node, Block):
            for stmt in node.statements:
                self._convert_node(stmt)
        elif isinstance(node, Assignment):
            val = self._convert_node(node.expr)
            self.constructor.write_var(node.var, self.current_block, val)
        elif isinstance(node, BinaryOp):
            l = self._convert_node(node.left)
            r = self._convert_node(node.right)
            inst = self.constructor.create_instruction(node.op, [l, r])
            self.current_block.add_instruction(inst)
            return inst
        elif isinstance(node, Variable):
            return self.constructor.read_var(node.name, self.current_block)
        elif isinstance(node, Constant):
            return self.constructor.create_constant(node.value)
        elif isinstance(node, If):
            self._convert_if(node)
        elif isinstance(node, While):
            self._convert_while(node)
        else:
            raise ValueError(f"Unknown AST node type: {type(node)}")
        return None
    
    def _convert_if(self, if_node: If):
        cond = self._convert_node(if_node.condition)
        then_blk = self.constructor.create_block()
        else_blk = self.constructor.create_block()
        merge_blk = self.constructor.create_block()
        
        br = self.constructor.create_branch(cond, then_blk, else_blk)
        self.current_block.add_instruction(br)
        then_blk.add_pred(self.current_block)
        else_blk.add_pred(self.current_block)
        
        entry_vars = dict(self.current_block.var_defs)
        
        self.current_block = then_blk
        for var, val in entry_vars.items():
            then_blk.var_defs[var] = val
        self._convert_node(if_node.then_stmt)
        if not then_blk.instructions or not isinstance(then_blk.instructions[-1], (JumpInstruction, BranchInstruction)):
            jmp = self.constructor.create_jump(merge_blk)
            then_blk.add_instruction(jmp)
            merge_blk.add_pred(then_blk)
        
        self.current_block = else_blk
        for var, val in entry_vars.items():
            else_blk.var_defs[var] = val
        if if_node.else_stmt:
            self._convert_node(if_node.else_stmt)
        if not else_blk.instructions or not isinstance(else_blk.instructions[-1], (JumpInstruction, BranchInstruction)):
            jmp = self.constructor.create_jump(merge_blk)
            else_blk.add_instruction(jmp)
            merge_blk.add_pred(else_blk)
        
        self.current_block = merge_blk
        for var in set(then_blk.var_defs.keys()) | set(else_blk.var_defs.keys()):
            t_val = then_blk.var_defs.get(var)
            e_val = else_blk.var_defs.get(var)
            if t_val and e_val and t_val != e_val:
                phi = self.constructor._create_phi(var, merge_blk)
                merge_blk.add_instruction(phi)
                merge_blk.var_defs[var] = phi
                phi.add_operand(then_blk, t_val)
                phi.add_operand(else_blk, e_val)
            elif t_val:
                merge_blk.var_defs[var] = t_val
            else:
                merge_blk.var_defs[var] = e_val
    
    def _convert_while(self, while_node: While):
        header = self.constructor.create_block()
        body = self.constructor.create_block()
        exit_ = self.constructor.create_block()
        
        entry = self.current_block
        entry_vars = dict(entry.var_defs)
        
        jmp = self.constructor.create_jump(header)
        entry.add_instruction(jmp)
        header.add_pred(entry)
        
        phi_nodes: Dict[str, PhiInstruction] = {}
        for var in entry_vars:
            phi = self.constructor._create_phi(var, header)
            header.add_instruction(phi)
            header.var_defs[var] = phi
            phi_nodes[var] = phi
        
        self.current_block = header
        cond = self._convert_node(while_node.condition)
        br = self.constructor.create_branch(cond, body, exit_)
        header.add_instruction(br)
        body.add_pred(header)
        exit_.add_pred(header)
        
        self.current_block = body
        for var, phi in phi_nodes.items():
            body.var_defs[var] = phi
        self._convert_node(while_node.body)
        body_end = self.current_block
        
        if not body_end.instructions or not isinstance(body_end.instructions[-1], (JumpInstruction, BranchInstruction)):
            back = self.constructor.create_jump(header)
            body_end.add_instruction(back)
            header.add_pred(body_end)
        
        for var, phi in phi_nodes.items():
            if entry_vars.get(var):
                phi.add_operand(entry, entry_vars[var])
            phi.add_operand(body_end, self.constructor.read_var(var, body_end))
        
        self.constructor.seal_block(body)
        self.constructor.seal_block(header)
        self.current_block = exit_
        
        for var, phi in phi_nodes.items():
            exit_.var_defs[var] = phi

# -------------------- 显示函数 --------------------
def display_ssa(constructor: BraunSSAConstructor, title: str = "SSA输出"):
    print(f"\n=== {title} ===")
    
    # 收集所有使用到的常量
    used_constants = set()
    for blk in constructor.blocks.values():
        for inst in blk.instructions:
            for op in inst.operands:
                if isinstance(op, ConstantValue):
                    used_constants.add(op)
        for phi in blk.phi_instructions:
            for _, val in phi.operands:
                if isinstance(val, ConstantValue):
                    used_constants.add(val)
    
    # 先显示常量定义（按ID排序）
    for const in sorted(used_constants, key=lambda c: c.id):
        val = const.constant_value
        if val is None:
            print(f"{const} = undef")
        else:
            print(f"{const} = const {val}")
    
    # 构建后继图并检测回边
    from collections import defaultdict
    succ = defaultdict(list)
    for blk in constructor.blocks.values():
        for inst in blk.instructions:
            if isinstance(inst, JumpInstruction):
                succ[blk.id].append(inst.target_block.id)
            elif isinstance(inst, BranchInstruction):
                succ[blk.id].extend([inst.true_block.id, inst.false_block.id])
    
    # 检测回边
    loop_headers = set()
    for src_id, dst_ids in succ.items():
        for dst_id in dst_ids:
            if dst_id < src_id:
                loop_headers.add(dst_id)
    
    # 显示各个块
    for blk in sorted(constructor.blocks.values(), key=lambda b: b.id):
        marker = " 🔄" if blk.id in loop_headers else ""
        print(f"\n{blk}{marker}:")
        print(f"  preds: {[p.id for p in blk.preds]}")
        
        if blk.phi_instructions:
            for phi in blk.phi_instructions:
                args = ", ".join(f"{pred}:{val}" for pred, val in phi.operands)
                print(f"  {phi} = φ({args})  [{phi.variable}]")
        
        for inst in blk.instructions:
            if isinstance(inst, JumpInstruction):
                print(f"  jmp {inst.target_block}")
            elif isinstance(inst, BranchInstruction):
                print(f"  br {inst.condition}, {inst.true_block}, {inst.false_block}")
            elif inst.opcode == "phi":
                continue  # phi已显示
            elif inst.operands:
                ops_str = ", ".join(str(op) for op in inst.operands)
                print(f"  {inst} = {inst.opcode} {ops_str}")

def reset_counters():
    Value._counter = 0
    BasicBlock._counter = 0
    ConstantValue._const_registry.clear()

# -------------------- 测例入口 --------------------
def run_if_test():
    assign1 = Assignment("x", Constant(5))
    assign2 = Assignment("y", Constant(3))
    cond = BinaryOp("gt", Variable("x"), Variable("y"))
    then_assign = Assignment("z", BinaryOp("add", Variable("x"), Variable("y")))
    else_assign = Assignment("z", BinaryOp("sub", Variable("x"), Variable("y")))
    if_stmt = If(cond, Block([then_assign]), Block([else_assign]))
    program = Block([assign1, assign2, if_stmt])
    
    reset_counters()
    constructor = ASTToSSAConverter().convert(program)
    display_ssa(constructor, "基础if测试")
    print("=" * 70)

def run_complex_if_while_test():
    init_sum = Assignment("sum", Constant(0))
    init_i = Assignment("i", Constant(0))
    
    if_cond = BinaryOp("gt", Variable("i"), Constant(2))
    then_expr = BinaryOp("add", Variable("sum"), BinaryOp("mul", Variable("i"), Constant(2)))
    then_assign = Assignment("sum", then_expr)
    else_assign = Assignment("sum", BinaryOp("add", Variable("sum"), Variable("i")))
    if_stmt = If(if_cond, Block([then_assign]), Block([else_assign]))
    
    inc_i = Assignment("i", BinaryOp("add", Variable("i"), Constant(1)))
    while_cond = BinaryOp("lt", Variable("i"), Constant(5))
    loop_body = Block([if_stmt, inc_i])
    while_stmt = While(while_cond, loop_body)
    
    result_assign = Assignment("result", BinaryOp("mul", Variable("sum"), Constant(2)))
    program = Block([init_sum, init_i, while_stmt, result_assign])
    
    reset_counters()
    constructor = ASTToSSAConverter().convert(program)
    display_ssa(constructor, "复杂嵌套测试")
    print("=" * 70)

if __name__ == "__main__":
    run_if_test()
    run_complex_if_while_test()