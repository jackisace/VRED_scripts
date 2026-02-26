import socket
import os
import subprocess
import sys


def play_bing():
    # speaker-test is the most 'raw' way to make a sound.
    # -t sine: plays a smooth tone (no file to stutter)
    # -f 1000: 1000Hz frequency (a clean 'beep')
    # -l 1: play only once
    # -X: exit after the tone

    # We use 'timeout' to ensure it doesn't hang the script
    cmd = "timeout 0.5s speaker-test -t sine -f 1000 -l 1 > /dev/null 2>&1"

    # Running this via sudo works because it hits the kernel-level driver
    subprocess.Popen(cmd, shell=True)

def start_listener(ip, port):
    # Create the socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Allow immediate reuse of the port if the script restarts
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            s.bind((ip, port))
            s.listen(1)
            print(f"[*] Listening on {ip}:{port} (ZSH/Kali)...")

            conn, addr = s.accept()
            with conn:
                print(f"\n[!] SHELL ACQUIRED from {addr[0]}:{addr[1]}")
                play_bing()

                # Basic interaction loop
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    print(data.decode('utf-8', errors='ignore'), end='')

        except PermissionError:
            print("[-] Error: Use 'sudo' to bind to port 443.")
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    # 0.0.0.0 listens on all interfaces (ETH, VPN, Localhost)
    start_listener('0.0.0.0', int(sys.argv[1]))
