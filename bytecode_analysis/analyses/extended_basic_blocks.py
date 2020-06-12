"""
extended_basic_blocks.py

Author: Robert McLaughlin <robert349@ucsb.edu>

Merges basic blocks A, B where:
1. A != B, and
2. B is not a root, and
2. B does not exist on an execution trace from a root to A (no backward edges)
    a. note: this is difficult and may be implemented incorrect?
3. One of the following applies:
    a. A is succeeded by B unconditionally, or
    b. A's successors include either B or C, but C proceeds directly to
       failure, unconditionally
"""

import decoder.instruction as instruction
from .basic_blocks import Block
import typing

class ExtendedBlock(Block):
    side_exits: typing.Set[Block]

    def __init__(self, thing=None):
        if isinstance(thing, ExtendedBlock):
            super().__init__(thing)
            self.side_exits = set(thing.side_exits)
        else:
            super().__init__(thing or [])
            self.side_exits = set()


def extend(blocks: typing.List[Block]) -> typing.List[Block]:
    failing_blocks = _blocks_which_fail(blocks)
    blocks = list(blocks)

    # first, find some "roots" of where to start execution traces
    # I'll begin with 1) the entry point, and 2) all PushBt targets
    roots = set([blocks[0]])
    
    for block in blocks:
        for instr in block:
            if isinstance(instr, instruction.PushBt):
                instr: instruction.PushBt
                target_block = _block_at(blocks, instr.offset)
                assert target_block is not None
                roots.add(target_block)


    # now, we'll do the following analysis:
    # 1. Create a work list of all roots
    # 2. For each block in the work list:
    #   a. while the block's successors are only failing blocks and (at most) one
    #      non-visited block, merge
    #   b. when recursive merge completes, if the last block branches
    #      to two (or more) non-failing nodes, add both to work list

    work_list = list(roots)
    while len(work_list) > 0:
        root = work_list.pop()
        if root not in blocks:
            # ignore orphans
            continue

        print('working on', id(root) & 0xffff)

        # if root ends in PopBt, it is an indirect jump and we must give up
        if isinstance(root[-1], instruction.PopBt):
            continue
        
        # this is a multi-decision node of sorts, don't bother
        if len(root.successors) > 2:
            continue

        # the block which we will be merging with
        merge_with = None

        # any side-exits (fail-exits)
        new_side_exit = None

        if len(root.successors) == 1:
            # unconditional jump, can always merge
            merge_with = next(iter(root.successors))
            assert merge_with is not None

        elif len(root.successors) == 2:
            it = iter(root.successors)
            s1 = next(it)
            s2 = next(it)
            assert s1 is not None
            assert s2 is not None

            if s1 not in failing_blocks:
                s1, s2 = s2, s1
            
            if s1 not in failing_blocks:
                # neither successor goes to failure, this is a decision
                # point, ignore
                continue

            merge_with = s2
            new_side_exit = s1
        
        else:
            # root has either 0 or >2 successors, no merge
            continue
        
        assert merge_with is not None

        if merge_with == root:
            # no self-merges
            continue

        if merge_with in work_list:
            # do not merge with other active roots
            continue
        
        if len(merge_with.predecessors) > 1:
            # do not merge with control flow joins
            continue

        #
        # perform the merge
        #

        # construct the new block
        newroot = ExtendedBlock(root)
        for instr in merge_with:
            newroot.append(instr)
        if new_side_exit != None:
            newroot.side_exits.add(new_side_exit)
        newroot.successors = merge_with.successors
        if root in newroot.successors:
            newroot.successors.remove(root)
            newroot.successors.add(root)
        if root in newroot.predecessors:
            newroot.predecessors.remove(root)
            newroot.predecessors.add(root)

        assert len(newroot) == len(root) + len(merge_with)

        # replace all references to the old root with the new root
        for block in blocks:
            if block == merge_with:
                print('found???')

            if root in block.successors:
                block.successors.remove(root)
                block.successors.add(newroot)
            if root in block.predecessors:
                block.predecessors.remove(root)
                block.predecessors.add(newroot)
            if isinstance(block, ExtendedBlock) and root in block.side_exits:
                block.side_exits.remove(root)
                block.side_exits.add(newroot)
        
        # remove the old root from the block list, add the new one
        print('huh', len(blocks), id(root) & 0xffff, id(newroot) & 0xffff, id(merge_with) & 0xffff)
        print('blocks_id', id(blocks))
        blocks.remove(root)
        blocks.remove(merge_with)
        blocks.append(newroot)
        if merge_with in work_list:
            work_list.remove(merge_with)
        if root in failing_blocks:
            failing_blocks.remove(root)
            failing_blocks.add(newroot)
        print(" ".join(list(map(lambda x: str(id(x) & 0xffff), blocks))))

        # add the new root to the worklist for analysis
        work_list.append(newroot)

    ret = list(sorted(blocks, key=lambda x: x[0].pc))
    for block in ret:
        assert all(map(lambda x: x in ret, block.successors))
        assert all(map(lambda x: x in ret, block.predecessors))
        if isinstance(block, ExtendedBlock):
            assert all(map(lambda x: x in ret, block.side_exits))
    return ret


def _blocks_which_fail(blocks: typing.List[Block]) -> typing.Set[Block]:
    """
    Identify and return all basic blocks which unconditionally proceed
    to matching failure.
    """
    # Start by identifying all blocks which terminate in a Fail instruction.
    failing_blocks = set(filter(
        lambda block: isinstance(block[-1], instruction.Fail),
        blocks,
    ))

    # Now find all blocks which proceed directly, unconditionally, to failure
    work_list = list(failing_blocks)
    while len(work_list) > 0:
        block = work_list.pop()

        for pred in block.predecessors:
            pred: Block

            if pred in failing_blocks:
                # ignore visited
                continue

            if isinstance(pred[-1], instruction.PopBt):
                # this block contains an indirect jump, just
                # ignore those for now
                continue

            if all(map(lambda x: x in failing_blocks, pred.successors)):
                # all of this predecessor's successors go to failure, so it
                # must also go to failure
                failing_blocks.append(block)
                work_list.append(block)

    return failing_blocks


def _block_at(blocks: typing.List[Block], addr: int) -> typing.Optional[Block]:
    for block in blocks:
        assert len(block) > 0

        if block[0].pc <= addr <= block[-1].pc:
            return block
    return None
