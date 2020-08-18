# Arab Security Cyber Wargame

# Challenge 1: meownetwork

```

Type : forensics

Name : meownetwork

Description : A hacker managed to get into meownetwork and leaked sensitive files of their respected baord members. 
The hacker uses ancient floppy disk technology, however our security team managed to get a disk image of the files 
he leaked. 
Can you find out what really leaked?

Points : 300


So the only material is  disk.img file.

Let's make some basics command :

```
![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/fileOf.png)


```
It is a partition table from a hard drive.

Maybe there are some files that were delete , let's try  foremost disk.img
```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/foremostOf.png)
![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/catOF.png)


```
Oh , there are  5 jpg files.

I try to use  stegsolve but nothing.

Then I just try to use steghide without password and boom : 
```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/steghideOf.png)


```
These files contains a lot of strings  the first one start with /9j/ and this base64.

I search a bit on google about the /9j/ and i found that is base64 encoded for jpeg files.
I try to use CyberChef and : 

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/catOf.png)


```
It looks like a part of a picture.

I try to use the order file like adding at the end of each file in ascending order and voilà :

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/ohcat.png)


```
We got something very interesting.

Time to download the file and to try some stegano.

After 20 minutes I found nothing. 

I understand that i am close to finish but nothing, I try a last thing that i forget to do 

because it was so obvious for me that it wouldn't work, it is crack the passphrase using stegcrack and : 

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/crackOf.png)

```
Enter the passphrase and it gives me flag.txt

```

![alt text](https://github.com/jeyan-m/CTF_Writeup/blob/master/ASCW_writeup/Forensics/chall_1/final.png)




