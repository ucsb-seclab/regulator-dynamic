"""
basic_blocks.py

Author: Robert McLaughlin <robert349@ucsb.edu>

Constructs basic blocks from an input regexp bytecode.


A basic block begins at:
    1. The start of the program
    2. The destination of a goto
    3. The instruction following a goto
    3. The stored instruction pointer of a push_bt
    4. The destination of a branching instruction (Check, etc)
    5. The assignment of cp to some absolute value
"""

from decoder.instruction import *
import decoder.bytecodes as b
import typing


class Block(list):
    successors: typing.Set['Block']
    predecessors: typing.Set['Block']

    def __init__(self, other = None):
        if isinstance(other, Block):
            super().__init__(list(other))
            self.successors = set(other.successors)
            self.predecessors = set(other.predecessors)
        else:
            super().__init__(other or [])
            self.successors = set()
            self.predecessors = set()

    def append(self, item: InstructionBase):
        assert isinstance(item, InstructionBase)
        super().append(item)

    def __getitem__(self, index: int) -> InstructionBase:
        return super().__getitem__(index)

    def __iter__(self) -> typing.Iterator[InstructionBase]:
        return super().__iter__()

    def __hash__(self):
        return id(self)

    def __eq__(self, other):
        return id(self) == id(other)


def basic_blocks(
        program: typing.List[InstructionBase]
    ) -> typing.List[Block]:

    # a list of edges between basic blocks, (from_addr, to_addr)
    block_breaks: typing.List[typing.Tuple[int, int]] = []

    for instr in program:
        assert type(instr).bytecode in b.instruction_widths
        width = b.instruction_widths[type(instr).bytecode]

        # figure out the fall-through program counter
        fall_through_pc = instr.pc + width

        # gotos
        if isinstance(instr, GoTo):
            instr: GoTo
            block_breaks.append((instr.pc, instr.goto))
            block_breaks.append((instr.pc, fall_through_pc))
        elif isinstance(instr, AdvanceCPAndGoto):
            instr: AdvanceCPAndGoto
            block_breaks.append((instr.pc, instr.goto))
            block_breaks.append((instr.pc, fall_through_pc))

        # address pushes/pops
        elif isinstance(instr, PushBt):
            instr: PushBt
            # not sure which PopBt will consume this just yet, but
            # the target will definitely need to be a leader
            block_breaks.append((-1, instr.offset))
        elif isinstance(instr, PopBt):
            instr: PopBt
            # not sure how it can be reached, but the fall-through address
            # MUST be a leader (if it exists)
            block_breaks.append((-1, fall_through_pc))

        # branches
        elif isinstance(instr, CheckChar):
            instr: CheckChar
            block_breaks.append((instr.pc, instr.goto_match))
            block_breaks.append((instr.pc, fall_through_pc))
        elif isinstance(instr, CheckNotChar):
            instr: CheckNotChar
            block_breaks.append((instr.pc, instr.goto_match))
            block_breaks.append((instr.pc, fall_through_pc))
        elif isinstance(instr, LoadCurrentChar):
            instr: LoadCurrentChar
            block_breaks.append((instr.pc, instr.goto_fail))
            block_breaks.append((instr.pc, fall_through_pc))
        elif isinstance(instr, SkipUntilBitInTable):
            instr: SkipUntilBitInTable
            block_breaks.append((instr.pc, instr.goto_match))
            block_breaks.append((instr.pc, instr.goto_fail))
            block_breaks.append((instr.pc, fall_through_pc))
        elif isinstance(instr, CheckCurrentPostion):
            instr: CheckCurrentPostion
            block_breaks.append((instr.pc, instr.goto_fail))
            block_breaks.append((instr.pc, fall_through_pc))

        # exits
        elif isinstance(instr, Succeed):
            # not sure how it can be reached, but the fall-through address
            # MUST be a leader (if it exists)
            block_breaks.append((-1, fall_through_pc))
        elif isinstance(instr, Fail):
            block_breaks.append((-1, fall_through_pc))

    leaders = set(map(lambda x: x[1], block_breaks))

    # break the blocks up
    blocks = []
    curr_block = None
    pc = 0
    for leader in sorted(leaders):
        assert pc < len(program)
        curr_block = Block()

        for instr in program[pc:]:
            if instr.pc >= leader:
                break
            pc += 1
            curr_block.append(instr)

        blocks.append(curr_block)
        assert len(curr_block) > 0

    # set predecessors / successors
    for src, dst in block_breaks:
        if src == -1:
            # we don't quite know how this leader can be reached just yet
            continue
        src_block = _block_at(blocks, src)
        dst_block = _block_at(blocks, dst)
        if src_block != None and dst_block != None:
            src_block.successors.add(dst_block)
            dst_block.predecessors.add(src_block)

    blocks = list(sorted(blocks, key=lambda b: b[0].pc))

    return blocks


def _block_at(blocks: typing.List[Block], addr: int) -> typing.Optional[Block]:
    for block in blocks:
        assert len(block) > 0

        if block[0].pc <= addr <= block[-1].pc:
            return block
    return None

