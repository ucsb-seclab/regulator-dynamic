import argparse
import decoder.decoder
import decoder.pretty_printer
import analyses.basic_blocks
import analyses.extended_basic_blocks


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        'FILE',
        help="A file to decode"
    )
    args = parser.parse_args()

    program = None
    with open(args.FILE, mode='rb') as fin:
        program = decoder.decoder.decode(fin.read())
    
    decoder.pretty_printer.pretty_print(program)
    return

    blocks = analyses.basic_blocks.basic_blocks(program)
    extended_blocks = analyses.extended_basic_blocks.extend(blocks)

    for block in extended_blocks:
        print('-----------------')
        for instr in block:
            print(instr)
        print('-----------------')
        print()
    

if __name__ == '__main__':
    main()
