# X86

import graphviz
import capstone
from graphviz import Digraph

cs = capstone.Cs(arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_64)
cs.detail = True
with open("issue", mode="rb") as f:
    bin1 = f.read()

blocks = {}


def disasm(data, address):
    block = []
    for ins in cs.disasm(data, address):
        block.append(hex(ins.address) + " " + ins.mnemonic + " " + ins.op_str)
        if ins.address in blocks:
            block.pop()
            return ins, "\l".join(block) + "\l", ins.address
        if ins.mnemonic[0] == 'j':
            return ins, "\l".join(block) + "\l", None
        if ins.mnemonic == 'ret':
            return ins, "\l".join(block) + "\l", None

    return ins, "\l".join(block) + "\l", None


start = 0x46B
end = 0x51B

stack = []
stack.append(start)
while len(stack) != 0:
    address = stack.pop()
    if address in blocks and address in range(start, end):
        continue
    eip, block, rel = disasm(bin1[address:end], address)
    blocks[address] = {"rel": [] if rel is None else [rel], "ins": block, "end": eip.address}
    if eip is None:
        continue
    if eip.mnemonic == 'jmp':
        if eip.operands[0].type == 1:
            continue
        blocks[address]["rel"].append(eip.operands[0].imm)
        stack.append(eip.operands[0].imm)
    elif eip.mnemonic[0] == 'j':
        if eip.operands[0].type == 1:
            continue
        blocks[address]["rel"].append(eip.address + eip.size)
        stack.append(eip.address + eip.size)
        blocks[address]["rel"].append(eip.operands[0].imm)
        stack.append(eip.operands[0].imm)

for b in blocks:
    for k, v in blocks.items():
        if k is not None and v["end"] is not None and b in range(k + 1, v["end"]):
            v["ins"] = v["ins"][:v["ins"].index(hex(b))]
            for i in range(0, len(v["rel"]) - 1):
                if v["rel"][i] > v["end"]:
                    v["rel"][i] = None
            if b not in v["rel"]:
                v["rel"].append(b)

dot = Digraph(comment='Graph')
dot.attr('node', shape='box')

for k, v in blocks.items():
    dot.node(hex(k), v['ins'])
    for i in v["rel"]:
        if i is not None:
            dot.edge(hex(k), hex(i), constraint='true')

dot.render('round-table.gv', view=True)
