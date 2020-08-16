# Arab Security Cyber Wargame

# Challenge 2: meownetwork

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


![alt text](base64OrNot.png)


```
This strings is encoded base64.
I use cyberchef to decode and after decoding base64 you have hexadecimal.
So you need to decode that too.

After that you have 'rar' you download the result and you have a rar which is encrypted.

```

![alt text](cyberchef)


```
Let's try to crack the passwword with rar2john.
First we need to have the hash and then crack it.

```

![alt text](getHash)
![alt text](inFile)

````
Once we got the hash, we need to crack the hash.


```

![alt text](hashCrack)

```
It is almost finish, let's get this flag.

```


![alt text](rarUnloking)

![alt text] (oh)


```

Here we go :

```


![alt text](voila)



