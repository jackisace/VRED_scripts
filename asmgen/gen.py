import ctypes, struct, sys
from keystone import *

badchars = b""

CODE = ""
with open(sys.argv[1]) as f:
    for line in f.readlines():
        if "badchars" in line:
            badchars = eval(line.split("=")[1].strip())
            continue
            
        linea = line.split("#")[0].strip()
        CODE += linea + ";"

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)

errors = []
for i, line in enumerate(CODE.strip().split(';')):
    if len(line) == 0:
        continue
    try:
        encoding, count = ks.asm(line)
        hex_code = " ".join([f"{b:02x}" for b in encoding])
        for e in encoding:
            if e in badchars:
                errors.append(str(f"FOUND {i} {hex_code:>34}: {line.strip()}"))
                break

    except:
        pass
    if ":" in line:
        print(f"\n{i} {hex_code:>40}: \t {line.strip()}")
    else:
        print(f"{i} {hex_code:>40}: \t\t {line.strip()}")


print()       
print("shellcode =  b\"\"")
shellcode = bytearray(sh)
for i in range(0, len(shellcode), 10):
    chunk = shellcode[i:i+10]
    line = ''.join(f'\\x{b:02x}' for b in chunk)
    print(f'shellcode += b"{line}"')

print("total bytes: ", len(shellcode))

if len(errors) > 0:
    print()
    for e in errors:
        print(e)
    print()
    print("badchars: ", " ".join([hex(c) for c in badchars]))


# ks = Ks(KS_ARCH_X86, KS_MODE_32)
# encoding, count = ks.asm(CODE)
# shellcode = bytearray(encoding)
 
# ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
#                                           ctypes.c_int(len(shellcode)),
#                                           ctypes.c_int(0x3000),
#                                           ctypes.c_int(0x40))
 
# buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
 
# ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
#                                      buf,
#                                      ctypes.c_int(len(shellcode)))
 
# print("Shellcode located at address %s" % hex(ptr))
# input("...ENTER TO EXECUTE SHELLCODE...")
 
# ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
#                                          ctypes.c_int(0),
#                                          ctypes.c_int(ptr),
#                                          ctypes.c_int(0),
#                                          ctypes.c_int(0),
#                                          ctypes.pointer(ctypes.c_int(0)))
 
# ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))


