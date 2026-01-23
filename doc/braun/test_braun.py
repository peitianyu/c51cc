class Block:
    __slots__ = ('name', 'preds', 'phis', 'defs', 'sealed', 'incomplete')
    def __init__(self, name):
        self.name = name
        self.preds = []
        self.phis = {}          # var -> Phi
        self.defs = {}          # var -> Value
        self.sealed = False
        self.incomplete = []    # [(var, phi), ...]

class Phi:
    __slots__ = ('var', 'ops', 'block')
    def __init__(self, var):
        self.var = var
        self.ops = []
        self.block = None

class Val:
    __slots__ = ('name',)
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return self.name

class Builder:
    def __init__(self):
        self.counter = 0
        self.blocks = {}
        self.const_cache = {}

    def fresh(self, prefix='v'):
        self.counter += 1
        return Val(f'{prefix}{self.counter}')

    def add_pred(self, block, pred):
        if pred not in block.preds:
            block.preds.append(pred)

    def write(self, block, var, val):
        block.defs[var] = val

    def read(self, block, var):
        if var in block.defs:
            return block.defs[var]
        return self.read_rec(block, var)

    def read_rec(self, block, var):
        if not block.sealed:
            phi = Phi(var)
            phi.block = block              # 补上
            block.phis[var] = phi
            block.incomplete.append((var, phi))
            block.defs[var] = phi
            return phi
        if len(block.preds) == 1:
            return self.read(block.preds[0], var)
        phi = Phi(var)
        phi.block = block                  # 补上
        block.phis[var] = phi
        block.defs[var] = phi
        return self.add_ops(phi)

    def add_ops(self, phi):
        for pred in phi.block.preds:
            val = self.read(pred, phi.var)
            phi.ops.append((pred, val))
        return self.try_remove_trivial(phi)

    def try_remove_trivial(self, phi):
        same = None
        for pred, val in phi.ops:
            if val == phi:
                continue          # 自引用跳过
            if same is None:
                same = val
            elif same != val:
                return phi        # 多值 ≠ trivial
        if same is None:
            same = self.const(None)
        # 替换使用
        phi.block.phis.pop(phi.var, None)
        phi.block.defs[phi.var] = same
        return same

    def const(self, c):
        key = f'const_{c}'
        if key not in self.const_cache:
            self.const_cache[key] = Val(key)
        return self.const_cache[key]

    def seal(self, block):
        block.sealed = True
        for var, phi in block.incomplete:
            self.add_ops(phi)
        block.incomplete.clear()

# ------------------- 测例 -------------------
def demo_irreducible():
    """跳转进循环（不可规约）"""
    b = Builder()
    entry = Block('entry')
    header = Block('header')
    body = Block('body')

    # 控制流边
    b.add_pred(header, entry)   # goto 进入
    b.add_pred(header, body)    # 回边
    b.add_pred(body, header)

    # 模拟 IR
    b.write(entry, 'x', b.const(1))
    b.seal(entry)

    x1 = b.read(header, 'x')        # 会生成 φ
    x2 = b.fresh()
    b.write(body, 'x', x2)
    b.seal(body)

    b.seal(header)                  # 完成 φ

    print('--- irreducible CFG SSA ---')
    print(f'{header.name}: {header.phis}')

    phi = header.phis['x']
    print('phi ops:', [(pred.name, val.name) for pred, val in phi.ops])

if __name__ == '__main__':
    demo_irreducible()