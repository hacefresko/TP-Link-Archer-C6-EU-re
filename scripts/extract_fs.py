import sys, subprocess, random, string, os

if len(sys.argv) != 2:
    print("[x] Usage: %s [file]" % sys.argv[0])
    exit()
minifs_file = sys.argv[1]

print("[+] Reading file")
try:
    f = open(minifs_file, "rb")
    contents = f.read()
    f.close()
except:
    print("[x] Something went wrong")
    exit()


print("[+] Running binwalk")
lzma_regions = []
p = subprocess.Popen(["binwalk", minifs_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
for line in p.stdout.readlines()[3:]:
    if line != b'\n':
        lzma_regions.append(int(line.decode("utf-8").split()[0]))


print("[+] Extracting filenames")
start_filenames = 0x00000020
end_filenames = start_filenames + contents[start_filenames:].find(b"\x00\x00\x00\x00")
filenames = [filename.decode("utf-8") for filename in contents[start_filenames:end_filenames].split(b"\x00")]
f =open("filenames.txt", "w")
f.write("\n".join(filenames))
f.close()

print("[+] Decompressing files")
merged_files = b""
aux_file = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
for i in range(len(lzma_regions)):
    if i < len(lzma_regions)-1:
        lzma = contents[lzma_regions[i]:lzma_regions[i+1]]
    else:
        lzma = contents[lzma_regions[i]:]

    f = open(aux_file + ".lzma", "wb")
    f.write(lzma)
    f.close()

    if os.system("unlzma -d %s.lzma" % aux_file) != 0:
        exit()

    f = open(aux_file, "rb")
    merged_files += f.read()
    f.close()

    os.remove(aux_file)

f =open("minifs.bin", "wb")
f.write(merged_files)
f.close()