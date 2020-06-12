import decoder.bytecodes
import decoder.instruction
import typing

def decode(b: bytes) -> typing.List[decoder.instruction.InstructionBase]:
    instrs = []
    pc = 0
    while pc < len(b):
        ins, pc = decoder.instruction.decode_one(b, pc)
        instrs.append(ins)
    return instrs
