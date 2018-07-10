#!/usr/bin/env python3

import re


constant_prefixes = [
    'EI_',
    'ELFCLASS',
    'ELFDATA',
    'ELFMAG',
    'ET_',
    'EV_',
    'NT_',
    'PT_',
    'SHN_',
    'SHT_',
]


if __name__ == '__main__':
    with open('/usr/include/elf.h', 'r') as f:
        elf_h = f.read()
    elf_h = re.sub(r'/\*.*?\*/', '', elf_h, flags=re.DOTALL)
    elf_h = re.sub(r'\\\n', '', elf_h)
    matches = re.findall(r'^#define\s+((?:' + '|'.join(constant_prefixes) + r')\w*)\s+(.+?)\s*$',
                         elf_h, re.MULTILINE)

    print('# Automatically generated from elf.h')
    for constant, value in matches:
        if value.startswith("'"):
            assert len(value) == 3 and value.endswith("'")
            value = hex(ord(value[1]))
        elif value.startswith('"'):
            continue
        if constant == 'DT_PROCNUM':
            value = next(match[1] for match in matches if match[0] == value)
        # Special case for SHF_EXCLUDE.
        if value == '(1U << 31)':
            value = '(1 << 31)'
        print(f'{constant} = {value}')
