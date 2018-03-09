def parse_symbol_file(file):
    symbols = {}
    for line in file:
        fields = line.split()
        name = fields[2]
        if fields[0] == '(null)':
            address = 0
        else:
            address = int(fields[0], 16)
        try:
            symbols[name].append(address)
        except KeyError:
            symbols[name] = [address]
    return symbols
