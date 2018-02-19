from drgn.elf import Symbol


def parse_symbol_file(file):
    symbols = {}
    for line in file:
        fields = line.split()
        sym_name = fields[2]
        if fields[0] == '(null)':
            address = 0
        else:
            address = int(fields[0], 16)
        symbol = Symbol(address=address)
        try:
            symbols[sym_name].append(symbol)
        except KeyError:
            symbols[sym_name] = [symbol]
    return symbols
