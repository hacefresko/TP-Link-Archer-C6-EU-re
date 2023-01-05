import serial, sys, os, time

BAUD_RATE = 115200
DELAY = 9

if os.geteuid() != 0:
    print("[x] Please, run %s as root" % sys.argv[0])
    exit()

if len(sys.argv) != 3:
    print("[x] Usage: %s [usb port] [output file]" % sys.argv[0])
    exit()

# Memory map of the flash with the format "name": (address, size)
flash_map = {
    "BOOTING": (0x00000000, 148),
    "UNUSED1": (0x00025000, 40),
    "BOOTCFG": (0x0002f000, 4),
    "FIRMWARE": (0x00030000, 3904),
    "FIRMWARE2": (0x00400000, 3904),
    "CONFIG": (0x007d0000, 64),
    "ISPCONFIG": (0x007e0000, 64),
    "UNUSED2": (0x007f0000, 40),
    "EXPLOG": (0x007fa000, 16),
    "PROFILE": (0x007fe000, 4),
    "RADIO": (0x007ff000, 4)
}

mem_addr = 0x41b97d70   # Memory address where the flash memory regions will be copied
max_dump_size = 16      # Maximum amount of memory that can be dumped (KB)

max_dump_size_bytes = max_dump_size * 1024

s = serial.Serial(sys.argv[1], BAUD_RATE)

f = open(sys.argv[2], "wb")
for region_name, region_data in flash_map.items():

    print("[+] Copying %s from flash to memory" % region_name)
    region_addr = region_data[0]
    region_size = region_data[1]
    region_size_bytes = region_size * 1024
    copy_flash_cmd = "flash -read %02x %02x %02x\r\n" % (region_addr, region_size_bytes, mem_addr)
    s.write(copy_flash_cmd.encode("utf-8"))
    s.readline().decode("utf-8")
    s.readline().decode("utf-8")
    
    bytes_read = 0
    while bytes_read < region_size_bytes:

        start_fragment = mem_addr + bytes_read

        bytes_left = (region_size_bytes - bytes_read)

        if bytes_left >= max_dump_size_bytes:
            end_fragment = start_fragment + max_dump_size_bytes - 16
            bytes_to_read = max_dump_size_bytes
        else:
            end_fragment = start_fragment + bytes_left - 16
            bytes_to_read = bytes_left

        bytes_read += bytes_to_read

        dump_mem_cmd = "mem -dump %02x %02x\r\n" % (start_fragment, bytes_to_read)
        print("[+] Dumping memory region from %s to %s" % (hex(start_fragment), hex(end_fragment)))   
        s.write(dump_mem_cmd.encode("utf-8"))
        s.readline().decode("utf-8")
        
        # Read a line until the last address of this region is read
        try:
            line = None
            while(line is None or int(line[:8], 16) != end_fragment):
                line = s.readline()

                # Fix random prompt characters appearing on the output lines
                if line[:4] == b'# # ':
                    line = line[4:]

                # Fix random new line in the output by merging 2 lines together if the first has not the correct length
                if len(line) != 83:
                    line = line[:-2] + s.readline()

                    # Fix random prompt characters appearing on the output line that is just added
                    if line[:4] == b'# # ':
                        line = line[4:]

                f.write(line)

        except ValueError:
            print("[x] There was an error: ")
            print(line)
            exit()

f.close()
s.close()
