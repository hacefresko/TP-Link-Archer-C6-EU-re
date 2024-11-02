import serial, sys, os, time

BAUD_RATE = 115200
DELAY = 9

if os.geteuid() != 0:
    print("[x] Please, run %s as root" % sys.argv[0])
    exit()

if len(sys.argv) != 3:
    print("[x] Usage: %s [usb port] [output file]" % sys.argv[0])
    exit()

def read_til_empty(s):
    # Sleep to make sure we read everything
    time.sleep(2)
    while True:
        if s.in_waiting > 0:
            s.read(s.in_waiting)
        else:
            break

max_dump_size = 16      # Maximum amount of memory that can be dumped (KB)

max_dump_size_bytes = max_dump_size * 1024

s = serial.Serial(sys.argv[1], BAUD_RATE)
read_til_empty(s)


# Get flash size
s.write("flash -layout \r\n".encode("utf-8"))
flash_size = s.read_until("Erase".encode("utf-8")).decode("utf-8")
flash_size = int(flash_size.split("Total Size(K): ")[1].split("\r")[0])
print("[+] Flash size: %sK" % flash_size)

# Find free (biggest) memory address to read from flash
# and also its size to do as few flash reads as possible
mem_addr = 0
max_read_size = 0

read_til_empty(s)
s.write("mem -show \r\n".encode("utf-8"))

# On a failed read we might've corrupted the memory,
# so a reboot COULD be required
s.readline()
s.readline()
test_line = s.readline().decode("utf-8")
if "wrong mem pool addr" not in test_line:
    print("[+] Memory OK!")
else:
    # Reboot to get fresh new memory
    print("[+] Memory corrupted. Rebooting router.")
    s.write("system -reboot \r\n".encode("utf-8"))
    print("[!] Sleeping for 30 seconds...")
    time.sleep(30)
    print("[+] Reboot complete!")
    read_til_empty(s)
    s.write("mem -show \r\n".encode("utf-8"))

mem_addr_list = s.read_until("SUMMARY".encode("utf-8")).decode("utf-8")
mem_addr_list = mem_addr_list.split("Heap Free Node:\r\n")[1]
mem_addr_list = mem_addr_list.split("\r\n")[3:]
for potential_mem_region in mem_addr_list:
   data = potential_mem_region.split()
   if potential_mem_region == '' or len(data) == 0:
       break
   potential_size = int(int(data[2]) / 1024)
   if potential_size > max_read_size:
       max_read_size = potential_size
       mem_addr = int(data[1], 16)
if max_read_size == 0:
    print("[-] Couldn't find memory region to read flash")
    exit(1)
else:
    # Just to be sure
    max_read_size -= 1

    # So we can find `end_segment`
    mem_addr += 16 - (mem_addr % 16)

    print("[+] Found free mem region at 0x%08x with size %sK" % (mem_addr, max_read_size))

f = open(sys.argv[2], "wb")

flash_read_head = 0
while flash_read_head < flash_size:
    # Print progress
    print("[!] Progress: %.2f%%" % (flash_read_head / flash_size))
    # Read as much as possible
    read_size = max_read_size
    # Unless we are apporaching the end of the flash
    if flash_size - flash_read_head < read_size:
        read_size = flash_size - flash_read_head

    read_start = flash_read_head * 1024
    read_end = read_start + read_size
    print("[+] Copying 0x%08x -> 0x%08x (%sK) from flash to memory" % (read_start, read_end, read_size))

    # Update head
    flash_read_head += read_size

    # Convert to bytes
    read_size *= 1024

    copy_flash_cmd = "flash -read %02x %02x %02x\r\n" % (read_start, read_size, mem_addr)
    s.write(copy_flash_cmd.encode("utf-8"))
    read_til_empty(s);

    bytes_read = 0
    while bytes_read < read_size:

        start_fragment = mem_addr + bytes_read

        bytes_left = (read_size - bytes_read)

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
