# X86

import graphviz
import capstone
from graphviz import Digraph


def draw(file, arch, mode, start, end):
    cs = capstone.Cs(arch=arch, mode=mode)
    cs.detail = True
    with open(file, mode="rb") as f:
        bin1 = f.read()

    blocks = {}

    def is_one_op(ins):
        if arch == capstone.CS_ARCH_X86:
            return ins.mnemonic[0] == 'j' and ins.mnemonic != 'jmp'
        if arch == capstone.CS_ARCH_ARM64:
            return ins.mnemonic[0:2] == 'b.'

    def is_two_op(ins):
        return ins.mnemonic == "cbz"

    def is_jmp(ins):
        if arch == capstone.CS_ARCH_X86:
            return ins.mnemonic == 'jmp'
        if arch == capstone.CS_ARCH_ARM64:
            return ins.mnemonic == 'b'

    def disasm(data, address):
        block = []
        for ins in cs.disasm(data, address):
            block.append(hex(ins.address) + " " + ins.mnemonic + " " + ins.op_str)
            if ins.address in blocks:
                block.pop()
                return ins, "\l".join(block) + "\l", ins.address
            if is_one_op(ins) or is_two_op(ins) or is_jmp(ins) or ins.mnemonic == 'ret':
                return ins, "\l".join(block) + "\l", None
        return ins, "\l".join(block) + "\l", None

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
        if is_jmp(eip):
            if eip.operands[0].type == 1:
                continue
            blocks[address]["rel"].append(eip.operands[0].imm)
            stack.append(eip.operands[0].imm)
        elif is_two_op(eip):
            blocks[address]["rel"].append(eip.address + eip.size)
            stack.append(eip.address + eip.size)
            if eip.operands[1].type == 1:
                continue
            blocks[address]["rel"].append(eip.operands[1].imm)
            stack.append(eip.operands[1].imm)
        elif is_one_op(eip):
            blocks[address]["rel"].append(eip.address + eip.size)
            stack.append(eip.address + eip.size)
            if eip.operands[0].type == 1:
                continue
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

    dot.render(file + '.gv', view=True)


if __name__ == '__main__':
    draw("issue", capstone.CS_ARCH_X86, capstone.CS_MODE_64, 0x46B, 0x51A)
    draw("libnative-lib.so", capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM, 0x0289C, 0x02E98)
