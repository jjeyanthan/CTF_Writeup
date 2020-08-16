# Arab Security Cyber Wargame

# Challenge 2: Fingerprint

```
Type : Forensics
Name : Finger Print
Description : Can You Spoof My Finger Print ???
Points : 300

```


```
We got 7 pictures ! 

The third one contain a string at the end.
```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/3.jpg)
![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/baseOrNot.png)


```
This strings is encoded base64.
I use cyberchef to decode and after decoding base64 you have hexadecimal.
So you need to decode that too.

After that you have 'rar' you download the result and you have a rar which is encrypted.

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/cyberChef.png)


```
Let's try to crack the passwword with rar2john.
First we need to have the hash and then crack it.

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/getHash.png)
![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/inFile.png)

```
Once we got the hash, we need to crack the hash.

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/hashCrack.png)

```
It is almost finish, let's get this flag.

```


![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/rarUnlocking.png)

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/Ohh.png)


```

Here we go :

```


![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_2/voila.png)



