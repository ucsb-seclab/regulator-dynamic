import typing
from .instruction import *

def pretty_print(program: typing.List[InstructionBase]):
    print("-------------------")

    max_addr = max(map(lambda x: x.pc, program))
    addr_width = len(hex(max_addr))

    instr_max = max(map(lambda x: len(x.bytecode), program))

    for instr in program:
        addr  = (hex(instr.pc)).rjust(addr_width)
        bytecode_desc = instr.bytecode.ljust(instr_max)

        v = dict((vars(instr)))
        del v['pc']
        for k in v:
            if 'goto' in k:
                v[k] = hex(v[k])
        
        if isinstance(instr, PushBt):
            v['offset'] = hex(v['offset'])

        print(addr, bytecode_desc, end=' ')
        if len(v) > 0:
            print(v)
        else:
            print()
