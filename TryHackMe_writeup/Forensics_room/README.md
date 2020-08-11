# Forensics

# 1.Volatility forensics


```
question :

Whats is the OS of this Dump? (Just write OS name in small)

```
volatility -f victim.raw imageinfo

```
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/robot/TryHackMe/Forensics_ctf/victim.raw)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028420a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002843d00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2019-05-02 18:11:45 UTC+0000
     Image local date and time : 2019-05-02 11:11:45 -0700




answer : the suggested  line tels us more about the Os : windows

question: 

Whats is the PID of SearchIndexer ? 
```
volatility -f victim.raw --profile=Win7SP1x64 pslist | grep SearchIndexer


```
0xfffffa8003367060 SearchIndexer.         2180    504     11      629      0      0 2019-05-02 18:03:32 UTC+0000

answer : 2180

question: What is the last directory accessed by the user?

```
volatility -f victim.raw --profil=Win7SP1x64 shellbags

```
***************************************************************************                                                                                           
Registry: \??\C:\Users\victim\AppData\Local\Microsoft\Windows\UsrClass.dat                                                                                            
Key: Local Settings\Software\Microsoft\Windows\Shell\BagMRU\1\2\0                                                                                                     
Last updated: 2019-04-27 10:48:33 UTC+0000                                                                                                                            
Value   Mru   File Name      Modified Date                  Create Date                    Access Date                    File Attr                 Path              
------- ----- -------------- ------------------------------ ------------------------------ ------------------------------ ------------------------- ----              
0       0     deleted_files  2019-04-27 10:30:26 UTC+0000   2019-04-27 10:38:24 UTC+0000   2019-04-27 10:38:24 UTC+0000   NI, DIR                   Z:\logs\deleted_fi
les                                                                                                                                                                   
***************************************************************************    

answer : deleted_files


```


# 2. Task2


```
question : There are many suspicious open port, which is it ?(protocol:port)

```
volatility -f victim.raw --profile=Win7SP1x64 netscan



```
Offset(P)          Proto    Local Address                  Foreign Address      State            Pid      Owner          Created
0x5c201ca0         UDPv4    0.0.0.0:5005                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c201ca0         UDPv6    :::5005                        *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c49cbb0         UDPv4    0.0.0.0:59471                  *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4a31c0         UDPv4    0.0.0.0:59472                  *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4a31c0         UDPv6    :::59472                       *:*                                   1368     svchost.exe    2019-05-02 18:03:06 UTC+0000
0x5c4ac630         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c4ac630         UDPv6    :::3702                        *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c519b30         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c537ec0         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c690360         UDPv4    0.0.0.0:0                      *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c690360         UDPv6    :::0                           *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c6918e0         UDPv4    0.0.0.0:5355                   *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c6918e0         UDPv6    :::5355                        *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c692940         UDPv4    0.0.0.0:5005                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c692ae0         UDPv4    0.0.0.0:5355                   *:*                                   1004     svchost.exe    2019-05-02 18:02:56 UTC+0000
0x5c7bac70         UDPv4    0.0.0.0:5004                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c7bac70         UDPv6    :::5004                        *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000
0x5c7f9600         UDPv4    0.0.0.0:3702                   *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c7f9600         UDPv6    :::3702                        *:*                                   1368     svchost.exe    2019-05-02 18:03:14 UTC+0000
0x5c44e1b0         TCPv4    0.0.0.0:5357                   0.0.0.0:0            LISTENING        4        System         
0x5c44e1b0         TCPv6    :::5357                        :::0                 LISTENING        4        System         
0x5c528010         TCPv4    0.0.0.0:445                    0.0.0.0:0            LISTENING        4        System         
0x5c528010         TCPv6    :::445                         :::0                 LISTENING        4        System         
0x5c534c60         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        504      services.exe   
0x5c534c60         TCPv6    :::49156                       :::0                 LISTENING        504      services.exe   
0x5c535010         TCPv4    0.0.0.0:49156                  0.0.0.0:0            LISTENING        504      services.exe   
0x5c6de720         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        920      svchost.exe    
0x5c6de720         TCPv6    :::49154                       :::0                 LISTENING        920      svchost.exe    
0x5c6e0df0         TCPv4    0.0.0.0:49154                  0.0.0.0:0            LISTENING        920      svchost.exe    
0x5c717460         TCPv4    0.0.0.0:49155                  0.0.0.0:0            LISTENING        512      lsass.exe      
0x5ca3ecc0         UDPv6    ::1:1900                       *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca452c0         UDPv6    fe80::6998:27e6:5653:fc35:1900 *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca4c2c0         UDPv6    fe80::1503:ac56:439f:bb6c:1900 *:*                                   1368     svchost.exe    2019-05-02 18:05:13 UTC+0000
0x5ca517c0         UDPv4    0.0.0.0:5004                   *:*                                   2464     wmpnetwk.exe   2019-05-02 18:05:14 UTC+0000


answer: The methodology consist of taking the first unsual port , check his PID and see if there are other  ip running on different
port with the same PID . This is the case for the first one -->  udp:5005  
```
```
question : Vads tag and execute protection are strong indicators of malicious processes, can you find which are they?

```
volatility -f victim.raw --profile=Win7SP1x64 malfind

```
Process: explorer.exe Pid: 1860 Address: 0x3ee0000
Process: svchost.exe Pid: 1820 Address: 0x24f0000
Process: wmpnetwk.exe Pid: 2464 Address: 0x280000

Malfind command : "The malfind command helps find hidden or injected code/DLLs in user mode memory,
based on characteristics such as VAD tag and page permissions."

answer: 1860,1820,2464




# 3. IOC SAGA

```
recap : 

We got 3 process that seem to be the infected one's , PID : 1860,1820,2464.
We need to extract them , to do the next step.
volatility -f victim.raw --profile=Win7SP1x64 memdump  -p 1860,1820,2464 -D dump/

1820.dmp  1860.dmp  2464.dmp 

question :
In lats task you have identified malicious processes, so lets dig into them and find some IOC's. you just need 
to find them and fill the blanks (You may search them on VirusTotal for more details :)

1)  'www.go****.ru' (write full url without any quotation marks)


```
strings 1820.dmp | grep 'www.go....\.ru'


```
answer : 

www.goporn.ru (the hint : This site is little naughty)


2) 'www.i****.com' (write full url without any quotation marks)
```
strings 1820.dmp | grep 'www.i....\.com'

```
answer: www.ikaka.com

3) 'www.ic******.com'
```

strings 1820.dmp | grep 'www.ic......\.com'



```
answer : www.icsalabs.com

4) 202.***.233.*** (Write full IP)
```
strings 1820.dmp | grep '202.***.233.***'

```
answer : 202.107.233.211

5) ***.200.**.164 (Write full IP)
```
strings 1820.dmp | grep '***.200.**.164'

```
answer : 209.200.12.164

6)209.190.***.***
```

strings 1820.dmp | grep '209.190.***.***'


```
answer :209.190.122.186

7) What is an unique environmental variable of PID 2464 
```
volatility -f victim.raw --profile=Win7SP1x64 envars | grep 2464

```
With the plugins envars we can find the environnement variable 
answer: OANOCACHE

```
#usefull ressource 


```
https://github.com/volatilityfoundation/volatility/wiki/Command-Reference

https://github.com/volatilityfoundation/volatility/wiki/Command-Reference-Mal
```
