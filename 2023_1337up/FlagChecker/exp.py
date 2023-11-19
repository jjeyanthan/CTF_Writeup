

from z3 import *


flag = [BitVec(f"flag[{i}]", 8) for i in range(22)] 
s=  Solver()
# INTIGRITI{
flag[0]=73
flag[1]=78
flag[2]=84
flag[3]=73
flag[4]=71
flag[5]=82
flag[6]=73
flag[7]=84
flag[8]=73
flag[9]=123

s.add(flag[18] * flag[7] & flag[12] ^ flag[2] == 36 )
s.add(flag[1] % flag[14] - flag[21] % flag[15] == -3 )
s.add(flag[10] + flag[4] * flag[11] - flag[20] == 5141 )
s.add(flag[19] + flag[12] * flag[0] ^ flag[16] == 8332 )
s.add(flag[9] ^ flag[13] * flag[8] & flag[16] == 113 )
s.add(flag[3] * flag[17] + flag[5] + flag[6] == 7090 )
s.add(flag[21] * flag[2] ^ flag[3] ^ flag[19] == 10521 )
s.add(flag[11] ^ flag[20] * flag[1] + flag[6] == 6787 )
s.add(flag[7] + flag[5] - flag[18] & flag[9] == 96 )
s.add(flag[12] * flag[8] - flag[10] + flag[4] == 8277 )
s.add(flag[16] ^ flag[17] * flag[13] + flag[14] == 4986 )
s.add(flag[0] * flag[15] + flag[3] == 7008 )
s.add(flag[13] + flag[18] * flag[2] & flag[5] ^ flag[10] == 118 )
s.add(flag[0] % flag[12] - flag[19] % flag[7] == 73 )
s.add(flag[14] + flag[21] * flag[16] - flag[8] == 11228 )
s.add(flag[3] + flag[17] * flag[9] ^ flag[11] == 11686 )
s.add(flag[15] ^ flag[4] * flag[20] & flag[1] == 95 )
s.add(flag[6] * flag[12] + flag[19] + flag[2] == 8490 )
s.add(flag[7] * flag[5] ^ flag[10] ^ flag[0] == 6869 )
s.add(flag[21] ^ flag[13] * flag[15] + flag[11] == 4936 )
s.add(flag[16] + flag[20] - flag[3] & flag[9] == 104 )
s.add(flag[18] * flag[1] - flag[4] + flag[14] == 5440 )
s.add(flag[8] ^ flag[6] * flag[17] + flag[12] == 7104 )
s.add(flag[11] * flag[2] + flag[15] == 6143)


print(s.check())
print(s.model())

flag_real=[0 for i in range(23)]


flag_real[0]=73
flag_real[1]=78
flag_real[2]=84
flag_real[3]=73
flag_real[4]=71
flag_real[5]=82
flag_real[6]=73
flag_real[7]=84
flag_real[8]=73
flag_real[9]=123
flag_real[18] = 70
flag_real[21] = 125
flag_real[11] = 72
flag_real[16] = 90
flag_real[20] = 87
flag_real[19] = 84
flag_real[12] = 114
flag_real[10] = 116
flag_real[14] = 51
flag_real[13] = 51
flag_real[15] = 95
flag_real[17] = 95


print(flag_real[0])
flagfinal = ""
for i in range(23):
    try:
        flagfinal+=chr(flag_real[i])
    except:
        pass
print(flagfinal)


# INTIGRITI{tHr33_Z_FTW}