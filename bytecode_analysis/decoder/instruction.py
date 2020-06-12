"""
instruction.py

Author: Robert McLaughlin <robert349@ucsb.edu>

Decodes bytecode instructions for V8 regexp engine
"""

from . import bytecodes
import struct
import typing
import warnings


_instruction_class_map = {}
def for_instruction(s):
    def f(cls_):
        _instruction_class_map[s] = cls_
        cls_.bytecode = s
        return cls_
    return f



class InstructionBase:
    """
    InstructionBase represents a single RegExp bytecode instruction.
    """

    bytecode: typing.ClassVar[str]

    def __init__(self, pc: int):
        assert pc is not None
        self.pc = pc


@for_instruction("PUSH_BT")
class PushBt(InstructionBase):
    offset: int = None

    def __init__(self, pc: int, offset: int):
        super().__init__(pc)
        self.offset = offset

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        offset = struct.unpack('=I', b[pc + 4: pc + 8])[0]
        return PushBt(pc, offset)


@for_instruction("SKIP_UNTIL_BIT_IN_TABLE")
class SkipUntilBitInTable(InstructionBase):
    load_offset: int = None
    num_advance: int = None
    bit_table: bytes = None
    goto_match: int  = None
    goto_fail: int   = None

    def __init__(
                self,
                pc: int,
                load_offset: int,
                num_advance: int,
                bit_table: int,
                goto_match: int,
                goto_fail: int,
            ):
        super().__init__(pc)
        self.load_offset = load_offset
        self.num_advance = num_advance
        self.bit_table = bit_table
        self.goto_match = goto_match
        self.goto_fail = goto_fail

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        # 3 bytes for load_offset :(
        load_offset = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        num_advance = struct.unpack('=h', b[pc+4 : pc+6])[0]
        bit_table = b[pc+8 : pc+8+16]
        goto_match = struct.unpack('=I', b[pc+24 : pc+24+4])[0]
        goto_fail = struct.unpack('=I', b[pc+28 : pc+28+4])[0]
        return SkipUntilBitInTable(pc, load_offset, num_advance, bit_table, goto_match, goto_fail)


@for_instruction('CHECK_CURRENT_POSITION')
class CheckCurrentPostion(InstructionBase):
    delta: int = None
    goto_fail: int = None

    def __init__(
                self,
                pc: int,
                delta: int,
                goto_fail: int,
            ):
        super().__init__(pc)
        self.delta = delta
        self.goto_fail = goto_fail

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        # 3 bytes for delta
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        goto_fail = struct.unpack('=I', b[pc + 4 : pc + 8])[0]
        return CheckCurrentPostion(pc, delta, goto_fail)


@for_instruction('LOAD_CURRENT_CHAR_UNCHECKED')
class LoadCurrentCharUnchecked(InstructionBase):
    delta: int = None

    def __init__(
                self,
                pc: int,
                delta: int,
            ):
        super().__init__(pc)
        self.delta = delta

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        # 3 bytes for delta
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        return LoadCurrentCharUnchecked(pc, delta)


@for_instruction('CHECK_CHAR')
class CheckChar(InstructionBase):
    char: str = None
    goto_match: int = None

    def __init__(
                self,
                pc: int,
                char: str,
                goto_match: int,
            ):
        super().__init__(pc)
        assert len(char) == 1
        self.char = char
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        char = chr(struct.unpack('=i', b[pc : pc+4])[0] >> 8)
        goto_match = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return CheckChar(pc, char, goto_match)


@for_instruction('ADVANCE_CP_AND_GOTO')
class AdvanceCPAndGoto(InstructionBase):
    advance: int = None
    goto: int = None
    
    def __init__(
                self,
                pc: int,
                advance: int,
                goto: int,
            ):
        super().__init__(pc)
        self.advance = advance
        self.goto = goto
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        advance = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        goto = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return AdvanceCPAndGoto(pc, advance, goto)


@for_instruction('CHECK_NOT_CHAR')
class CheckNotChar(InstructionBase):
    char: str = None
    goto_match: int = None

    def __init__(
                self,
                pc: int,
                char: str,
                goto_match: int,
            ):
        super().__init__(pc)
        assert len(char) == 1
        self.char = char
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        char = chr(struct.unpack('=i', b[pc : pc+4])[0] >> 8)
        goto_match = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return CheckNotChar(pc, char, goto_match)


@for_instruction('LOAD_CURRENT_CHAR')
class LoadCurrentChar(InstructionBase):
    delta: int = None
    goto_fail: int = None

    def __init__(
                self,
                pc: int,
                delta: int,
                goto_fail: int,
            ):
        super().__init__(pc)
        self.delta = delta
        self.goto_fail = goto_fail

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        goto_fail = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return LoadCurrentChar(pc, delta, goto_fail)


@for_instruction('PUSH_CP')
class PushCP(InstructionBase):

    def __init__(self, pc: int):
        super().__init__(pc)
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        return PushCP(pc)
    

@for_instruction('SET_REGISTER_TO_CP')
class SetRegisterToCP(InstructionBase):
    reg_id: int = None
    delta: int = None

    def __init__(self, pc: int, reg_id: int, delta: int):
        super().__init__(pc)
        self.reg_id = reg_id
        self.delta = delta
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        delta = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        return SetRegisterToCP(pc, reg_id, delta)


@for_instruction('ADVANCE_CP')
class AdvanceCP(InstructionBase):
    delta: int = None

    def __init__(self, pc: int, delta: int):
        super().__init__(pc)
        self.delta = delta
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        return AdvanceCP(pc, delta)


@for_instruction('SUCCEED')
class Succeed(InstructionBase):
    def __init__(self, pc: int):
        super().__init__(pc)
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        return Succeed(pc)


@for_instruction('SET_REGISTER')
class SetRegister(InstructionBase):
    reg_id: int = None
    val: int = None

    def __init__(self, pc: int, reg_id: int, val: int):
        super().__init__(pc)
        self.reg_id = reg_id
        self.val = val
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        val = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return SetRegister(pc, reg_id, val)


@for_instruction('POP_CP')
class PopCP(InstructionBase):
    def __init__(self, pc: int):
        super().__init__(pc)
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        return PopCP(pc)


@for_instruction('GOTO')
class GoTo(InstructionBase):
    goto: int = None

    def __init__(self, pc: int, goto: int):
        super().__init__(pc)
        self.goto = goto
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        goto = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return GoTo(pc, goto)


@for_instruction('FAIL')
class Fail(InstructionBase):
    def __init__(self, pc: int):
        super().__init__(pc)
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        return Fail(pc)


@for_instruction('POP_BT')
class PopBt(InstructionBase):
    def __init__(self, pc: int):
        super().__init__(pc)
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        return PopBt(pc)


@for_instruction('CHECK_GREEDY')
class CheckGreedy(InstructionBase):
    goto_match: int = None

    def __init__(self, pc: int, goto_match: int):
        super().__init__(pc)
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        goto_match = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        return CheckGreedy(pc, goto_match)


@for_instruction('CHECK_GT')
class CheckGt(InstructionBase):
    limit: int = None
    goto_match: int = None

    def __init__(self, pc: int, limit: int, goto_match: int):
        super().__init__(pc)
        self.limit = limit
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        limit = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        goto_match = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return CheckGt(pc, limit, goto_match)


@for_instruction('CHECK_LT')
class CheckLt(InstructionBase):
    limit: int = None
    goto_match: int = None

    def __init__(self, pc: int, limit: int, goto_match: int):
        super().__init__(pc)
        self.limit = limit
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        limit = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        goto_match = struct.unpack('=I', b[pc+4 : pc+8])[0]
        return CheckGt(pc, limit, goto_match)


@for_instruction('CHECK_CHAR_IN_RANGE')
class CheckCharInRange(InstructionBase):
    from_: int = None
    to: int = None
    goto_match: int = None

    def __init__(self, pc: int, from_: int, to: int, goto_match: int):
        super().__init__(pc)
        self.from_ = from_
        self.to = to
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        from_ = struct.unpack('=H', b[pc+4 : pc+4+2])[0]
        to = struct.unpack('=H', b[pc+6 : pc+6+2])[0]
        goto_match = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        return CheckCharInRange(pc, from_, to, goto_match)


@for_instruction('SKIP_UNTIL_CHAR_POS_CHECKED')
class SkipUntilCharPosChecked(InstructionBase):
    delta: int = None
    advance: int = None
    char: str = None
    max_delta: int = None
    goto_fail: int = None
    goto_match: int = None

    def __init__(
                self,
                pc: int,
                delta: int,
                advance: int,
                char: str,
                max_delta: int,
                goto_fail: int,
                goto_match: int,
            ):
        assert len(char) == 1
        super().__init__(pc)
        self.delta = delta
        self.advance = advance
        self.char = char
        self.max_delta = max_delta
        self.goto_fail = goto_fail
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        advance = struct.unpack('=h', b[pc+4 : pc+4+2])[0]
        char = chr(struct.unpack('=H', b[pc+6 : pc+6+2])[0])
        max_delta = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        goto_match = struct.unpack('=I', b[pc+12 : pc+12+4])[0]
        goto_fail = struct.unpack('=I', b[pc+16 : pc+16+4])[0]
        return SkipUntilCharPosChecked(pc, delta, advance, char, max_delta, goto_fail, goto_match)


@for_instruction('CHECK_CHAR_NOT_IN_RANGE')
class CheckCharNotInRange(InstructionBase):
    from_: int = None
    to: int = None
    goto_match: int = None

    def __init__(self, pc: int, from_: int, to: int, goto_match: int):
        super().__init__(pc)
        self.from_ = from_
        self.to = to
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        from_ = struct.unpack('=H', b[pc+4 : pc+4+2])[0]
        to = struct.unpack('=H', b[pc+6 : pc+6+2])[0]
        goto_match = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        return CheckCharInRange(pc, from_, to, goto_match)


@for_instruction('PUSH_REGISTER')
class PushRegister(InstructionBase):
    reg_id: int = None

    def __init__(self, pc: int, reg_id: int):
        super().__init__(pc)
        self.reg_id = reg_id
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        return PushRegister(pc, reg_id)


@for_instruction('AND_CHECK_CHAR')
class AndCheckChar(InstructionBase):
    char: str = None
    mask: int = None
    goto_match: int = None

    def __init__(self, pc: int, char: str, mask: int, goto_match: int):
        assert len(char) == 1
        super().__init__(pc)
        self.char = char
        self.mask = mask
        self.goto_match = goto_match

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        char = chr(struct.unpack('=i', b[pc : pc+4])[0] >> 8)
        mask = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        goto_match = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        return AndCheckChar(pc, char, mask, goto_match)


@for_instruction('AND_CHECK_NOT_CHAR')
class AndCheckNotChar(InstructionBase):
    char: str = None
    mask: int = None
    goto_match: int = None

    def __init__(self, pc: int, char: str, mask: int, goto_match: int):
        assert len(char) == 1
        super().__init__(pc)
        self.char = char
        self.mask = mask
        self.goto_match = goto_match

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        char = chr(struct.unpack('=i', b[pc : pc+4])[0] >> 8)
        mask = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        goto_match = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        return AndCheckNotChar(pc, char, mask, goto_match)


@for_instruction('CHECK_REGISTER_LT')
class CheckRegisterLt(InstructionBase):
    reg_id: int = None
    limit: int = None
    goto_match: int = None

    def __init__(self, pc: int, reg_id: int, limit: int, goto_match: int):
        super().__init__(pc)
        self.reg_id = reg_id
        self.limit = limit
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        limit = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        goto_match = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        return CheckRegisterLt(pc, reg_id, limit, goto_match)


@for_instruction('ADVANCE_REGISTER')
class AdvanceRegister(InstructionBase):
    reg_id: int = None
    advance: int = None

    def __init__(self, pc: int, reg_id: int, advance: int):
        super().__init__(pc)
        self.reg_id = reg_id
        self.advance = advance
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        advance = struct.unpack('=I', b[pc+4 : pc+4+4])[0] >> 8
        return AdvanceRegister(pc, reg_id, advance)


@for_instruction('POP_REGISTER')
class PopRegister(InstructionBase):
    reg_id: int = None

    def __init__(self, pc: int, reg_id: int):
        super().__init__(pc)
        self.reg_id = reg_id

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        return PopRegister(pc, reg_id)


@for_instruction('SKIP_UNTIL_CHAR')
class SkipUntilChar(InstructionBase):
    delta: int = None
    advance: int = None
    char: str = None
    goto_match: int = None
    goto_fail: int = None

    def __init__(
                self,
                pc: int,
                delta: int,
                advance: int,
                char: str,
                goto_match: int,
                goto_fail: int,
            ):
        assert len(char) == 1
        super().__init__(pc)
        self.delta = delta
        self.advance = advance
        self.char = char
        self.goto_match = goto_match
        self.goto_fail = goto_fail

    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        advance = struct.unpack('=h', b[pc+4 : pc+4+2])[0]
        char = chr(struct.unpack('=H', b[pc+6 : pc+6+2])[0])
        goto_match = struct.unpack('=I', b[pc+8 : pc+8+4])[0]
        goto_fail = struct.unpack('=I', b[pc+12 : pc+12+4])[0]
        return SkipUntilChar(pc, delta, advance, char, goto_fail, goto_match)


@for_instruction('CHECK_REGISTER_GE')
class CheckRegisterGe(InstructionBase):
    reg_id: int = None
    limit: int = None
    goto_match: int = None

    def __init__(self, pc: int, reg_id: int, limit: int, goto_match: int):
        super().__init__(pc)
        self.reg_id = reg_id
        self.limit = limit
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        reg_id = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        limit = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        goto_match = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        return CheckRegisterGe(pc, reg_id, limit, goto_match)


@for_instruction('CHECK_NOT_AT_START')
class CheckNotAtStart(InstructionBase):
    delta: int = None
    goto_match: int = None

    def __init__(self, pc: int, delta: int, goto_match: int):
        super().__init__(pc)
        self.delta = delta
        self.goto_match = goto_match
    
    @classmethod
    def parse(cls, b: bytes, pc: int) -> InstructionBase:
        delta = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        goto_match = struct.unpack('=I', b[pc+4 : pc+4+4])[0]
        return CheckNotAtStart(pc, delta, goto_match)


@for_instruction('SET_CURRENT_POSITION_FROM_END')
class SetCurrentPositionFromEnd(InstructionBase):
    by: int = None

    def __init__(self, pc: int, by: int):
        super().__init__(pc)
        self.by = by

    @classmethod
    def parse(self, b: bytes, pc: int) -> InstructionBase:
        by = struct.unpack('=i', b[pc : pc+4])[0] >> 8
        return SetCurrentPositionFromEnd(pc, by)


_not_implemented_instructions = set(
        bytecodes.instruction_to_byte.keys()
    ).difference(
        _instruction_class_map.keys()
    )

for instr_name in _not_implemented_instructions:
    warnings.warn(Warning("not implemented:", instr_name))


def decode_one(b: bytes, pc: int) -> (InstructionBase, int):
    """
    Decodes one instruction.

    Returns the decoded instruction and the new program counter
    after advancing past this instruction.
    """
    code = struct.unpack('=B', b[pc:pc+1])[0]
    
    if not code in bytecodes.byte_to_instruction:
        raise Exception("Unknown bytecode: " + hex(code) + " at " + hex(pc))

    instr = bytecodes.byte_to_instruction[code]
    if not instr in _instruction_class_map:
        raise Exception("Did not implement " + instr + " yet")

    if not instr in bytecodes.instruction_widths:
        raise Exception("Could not lookup width for " + instr)

    next_pc = bytecodes.instruction_widths[instr] + pc

    cls_ = _instruction_class_map[instr]
    return (cls_.parse(b, pc), next_pc)
