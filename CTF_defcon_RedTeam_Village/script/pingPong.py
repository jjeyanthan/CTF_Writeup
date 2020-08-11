#!/bin/env/python3 


import socket 
import time

HOST="164.90.147.2"
PORT=2346

def netcat(host,port):
    myS= socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    myS.connect((host,port))
    time.sleep(0.5)
    data=[]

    capt=myS.recv(1024).decode("utf8")
    firstElem=capt[593]
    print(firstElem)
    data.append(firstElem)
    envoye=firstElem.encode("utf8")
    myS.sendall(envoye)
    
    while '}' not in data:
    
        capt=myS.recv(1024).decode("utf8")
        time.sleep(0.5)
        data.append(capt[0])
        print(capt[0])
        element= capt[0]
        envoye=element.encode("utf8")
        myS.sendall(envoye)


    
    myS.close()
    print(data)

netcat(HOST,PORT)