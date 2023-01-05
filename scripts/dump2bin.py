# Modified https://github.com/gmbnomis/uboot-mdb-dump/blob/master/uboot_mdb_to_image.py

import sys, io

BYTES_IN_LINE = 0x10 # Number of bytes to expect in each line

c_addr = None
hex_to_ch = {}

ascii_stdin = io.TextIOWrapper(sys.stdin.buffer, encoding='ascii', errors='strict')

for line in ascii_stdin:
    line = line[:-1] # Strip the linefeed (we can't strip all white
                     # space here, think of a line of 0x20s)
    data, ascii_data = line.split(" \t  ", maxsplit = 1)
    straddr, strdata = data.split(maxsplit = 1)
    addr = int.from_bytes(bytes.fromhex(straddr[:-1]), byteorder = 'big')

    c_addr = addr
    strdata = strdata.replace("- ", "")
    data = bytes.fromhex(strdata)
    if len(data) != BYTES_IN_LINE:
        sys.exit("Unexpected number of bytes in line: '%s'" % line)

    sys.stdout.buffer.write(data)