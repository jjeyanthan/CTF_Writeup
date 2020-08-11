# Volatility



volatility -f cridex.vmem imageinfo 

# profile

```
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/home/robot/TryHackMe/volatily/cridex.vmem)
                      PAE type : PAE
                           DTB : 0x2fe000L
                          KDBG : 0x80545ae0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-07-22 02:45:08 UTC+0000
     Image local date and time : 2012-07-21 22:45:08 -0400



```
This line interest us :
```
Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86) 

```
The vm was instantiated with WinXPSP2x86 , so our profile will be : WinXPSP2x86


# pslist (list of the process during the dump)
I.Find a given process.

```
find the PID  smss.exe process?

```
volatility -f cridex.vmem --profile=WinXPSP2x86 pslist | grep smss.exe 


```
it gives : 0x822f1020 smss.exe                368      4      3       19 ------      0 2012-07-22 02:42:31 UTC+0000

the PID (process id of the smss.exe process is 368.
```
II.Finding hidden process.


```
question: What process has only one 'False' listed?

```
volatility -f cridex.vmem --profile=WinXPSP2x86 psxview

```
Offset(P)  Name                    PID pslist psscan thrdproc pspcid csrss session deskthrd ExitTime
---------- -------------------- ------ ------ ------ -------- ------ ----- ------- -------- --------
0x02498700 winlogon.exe            608 True   True   True     True   True  True    True     
0x02511360 svchost.exe             824 True   True   True     True   True  True    True     
0x022e8da0 alg.exe                 788 True   True   True     True   True  True    True     
0x020b17b8 spoolsv.exe            1512 True   True   True     True   True  True    True     
0x0202ab28 services.exe            652 True   True   True     True   True  True    True     
0x02495650 svchost.exe            1220 True   True   True     True   True  True    True     
0x0207bda0 reader_sl.exe          1640 True   True   True     True   True  True    True     
0x025001d0 svchost.exe            1004 True   True   True     True   True  True    True     
0x02029ab8 svchost.exe             908 True   True   True     True   True  True    True     
0x023fcda0 wuauclt.exe            1136 True   True   True     True   True  True    True     
0x0225bda0 wuauclt.exe            1588 True   True   True     True   True  True    True     
0x0202a3b8 lsass.exe               664 True   True   True     True   True  True    True     
0x023dea70 explorer.exe           1484 True   True   True     True   True  True    True     
0x023dfda0 svchost.exe            1056 True   True   True     True   True  True    True     
0x024f1020 smss.exe                368 True   True   True     True   False False   False    
0x025c89c8 System                    4 True   True   True     True   False False   False    
0x024a0598 csrss.exe               584 True   True   True     True   False True    True  


The last line contain only one false, process name : csrss.exe
```

# ldrmodules 


```
question :  Which process has all three columns listed as 'False' (other than System)?

```
volatility -f cridex.vmem --profile=WinXPSP2x86 ldrmodules


```
Pid      Process              Base       InLoad InInit InMem MappedPath
-------- -------------------- ---------- ------ ------ ----- ----------
       4 System               0x7c900000 False  False  False \WINDOWS\system32\ntdll.dll
     368 smss.exe             0x48580000 True   False  True  \WINDOWS\system32\smss.exe
     368 smss.exe             0x7c900000 True   True   True  \WINDOWS\system32\ntdll.dll
     584 csrss.exe            0x00460000 False  False  False \WINDOWS\Fonts\vgasys.fon

It is csrss.exe

```

# malfind  
```
Thanks to this pluggins we can know if there is a code injected.

```
volatility -f cridex.vmem --profile=WinXPSP2x86 malfind -D dump/



```
question :  How many files does this generate? 

process.0x81e7bda0.0x3d0000.dmp    process.0x82298700.0x4c540000.dmp  process.0x82298700.0x554c0000.dmp  process.0x82298700.0x73f40000.dmp
process.0x821dea70.0x1460000.dmp   process.0x82298700.0x4dc40000.dmp  process.0x82298700.0x5de10000.dmp  process.0x82298700.0xf9e0000.dmp
process.0x82298700.0x13410000.dmp  process.0x82298700.0x4ee0000.dmp   process.0x82298700.0x6a230000.dmp  process.0x822a0598.0x7f6f0000.dmp

There is 12 files.
```


# dlllist & dlldump

```
Dlllist enumerate all the dll use by a process with the command :  volatility -f cridex.vmem --profile=WinXPSP2x86 dlllist -p PID
In this question we need to dump dll used by the infected process : csrss.exe (PID 584 )

```
 volatility -f cridex.vmem --profile=WinXPSP2x86 --pid=584  dlldump -D /allDll



```
Process(V) Name                 Module Base Module Name          Result
---------- -------------------- ----------- -------------------- ------
0x822a0598 csrss.exe            0x04a680000 csrss.exe            OK: module.584.24a0598.4a680000.dll
0x822a0598 csrss.exe            0x07c900000 ntdll.dll            OK: module.584.24a0598.7c900000.dll
0x822a0598 csrss.exe            0x075b40000 CSRSRV.dll           OK: module.584.24a0598.75b40000.dll
0x822a0598 csrss.exe            0x077f10000 GDI32.dll            OK: module.584.24a0598.77f10000.dll
0x822a0598 csrss.exe            0x07e720000 sxs.dll              OK: module.584.24a0598.7e720000.dll
0x822a0598 csrss.exe            0x077e70000 RPCRT4.dll           OK: module.584.24a0598.77e70000.dll
0x822a0598 csrss.exe            0x077dd0000 ADVAPI32.dll         OK: module.584.24a0598.77dd0000.dll
0x822a0598 csrss.exe            0x077fe0000 Secur32.dll          OK: module.584.24a0598.77fe0000.dll
0x822a0598 csrss.exe            0x075b50000 basesrv.dll          OK: module.584.24a0598.75b50000.dll
0x822a0598 csrss.exe            0x07c800000 KERNEL32.dll         OK: module.584.24a0598.7c800000.dll
0x822a0598 csrss.exe            0x07e410000 USER32.dll           OK: module.584.24a0598.7e410000.dll
0x822a0598 csrss.exe            0x075b60000 winsrv.dll           OK: module.584.24a0598.75b60000.dll

There is 12 dll that were used by the infected process.
```


# Post action = Virus Total


1) Virus total recognize extracted dll as virus


![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/TryHackMe_writeup/Volatility/virusOrNot.png)



2) Last question name of the malware that virus total find ?



![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/TryHackMe_writeup/Volatility/virus_name.png)
