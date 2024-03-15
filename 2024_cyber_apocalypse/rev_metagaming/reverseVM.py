from z3 import *


# def rotr(n, r, num_bits=32):
#     if r < 0:
#         return rotl(n,-r)
#     return ((n >> r) | (n << (num_bits - (r&31)))) & ((1 << num_bits) - 1)


# def rotl(n, r, num_bits=32):
#     if r < 0:
#         return rotr(n,-r)
#     return ((n << r) | (n >> (num_bits - (r&31)))) & ((1 << num_bits) - 1)

## for z3

def rotr(n, r, num_bits=32):
    return ((n >> r) | (n << (num_bits - (r&31)))) & ((1 << num_bits) - 1)
   

def rotl(n, r, num_bits=32):
    return (n >> (num_bits - (r&31))) & ((1 << num_bits) - 1)


def rotl2(n, r, num_bits=32):
    try:
        return  rotl(n,r)
    except:
        return rotr(n,-r)


s= Solver()


flag = [BitVec(f'flag{i}',32) for i in range(40)] 

for i in range(40):
    s.add(flag[i] > 0x20)
    s.add(flag[i] < 0x7e)



s.add(flag[0]==ord('H'))
s.add(flag[1]==ord('T'))
s.add(flag[2]==ord('B'))
s.add(flag[3]==ord('{'))
s.add(flag[39]==ord('}'))




regs = [BitVecVal(0,32) for i in range(15)]  


def insn_t(opcode,op0,op1):
    if opcode == 0:
        regs[op0]=flag[op1]
    elif opcode == 1:
        regs[op0]=op1        
    elif opcode == 2:
        regs[op0]=(regs[op0]^op1)  
    elif opcode == 3:
        regs[op0]=(regs[op0]^regs[op1])        
    elif opcode == 4:
        regs[op0]|=op1           
    elif opcode == 5:
        regs[op0]|=regs[op1]         
    elif opcode == 6:
        regs[op0]&=op1         
    elif opcode == 7:
        regs[op0]&=regs[op1]         
    elif opcode == 8:
        regs[op0]+=op1         
    elif opcode == 9:
        regs[op0]+=regs[op1]       
    elif opcode == 10:
        regs[op0]= regs[op0] - op1          
    elif opcode == 11:
        regs[op0]=regs[op0] - regs[op1]        
    elif opcode == 12:
        regs[op0]= regs[op0] * op1  
    elif opcode == 13:
        regs[op0]=regs[op0] *regs[op1]     
    elif opcode == 14:
        pass        
    elif opcode == 15:
        pass
    elif opcode == 16:
        regs[op0]=  rotr(regs[op0],op1) #RotateRight(regs[op0], BitVecVal(op1,32))     
    elif opcode == 17:
        regs[op0]= rotr(regs[op0],regs[op1])  #RotateRight(regs[op0],regs[op1])  
    elif opcode == 18:
        regs[op0]= rotl2(regs[op0],op1)   #RotateLeft(regs[op0],BitVecVal(op1,32))     
    elif opcode == 19:
        regs[op0]= rotl2(regs[op0],regs[op1])   #RotateLeft(regs[op0],regs[op1])        
    elif opcode == 20: 
        regs[op0]=regs[op1]      
    elif opcode == 21:
        regs[op0]=0        
    elif opcode == 22:
        regs[op0]>>=op1        
    elif opcode == 23:
        regs[op0]>>=regs[op1]       
    elif opcode == 24:
        regs[op0]<<=op1         
    elif opcode == 25:
        regs[op0]<<=regs[op1]
    else:
        assert False
    

     
insn_t(12, 13, 10),
insn_t(21, 0, 0),
insn_t(0, 13, 13),
insn_t(0, 14, 0),
insn_t(24, 14, 0),
insn_t(5, 0, 14),
insn_t(0, 14, 1),
insn_t(7, 11, 11),
insn_t(24, 14, 8),
insn_t(5, 0, 14),
insn_t(0, 14, 2),
insn_t(2, 10, 11),
insn_t(24, 14, 16),
insn_t(18, 12, 11),
insn_t(5, 0, 14),
insn_t(0, 14, 3),
insn_t(0, 11, 11),
insn_t(24, 14, 24),
insn_t(13, 10, 10),
insn_t(5, 0, 14),
insn_t(2, 11, 13),
insn_t(21, 1, 0),
insn_t(0, 14, 4),
insn_t(24, 14, 0),
insn_t(5, 1, 14),
insn_t(6, 11, 12),
insn_t(0, 14, 5),
insn_t(8, 10, 10),
insn_t(24, 14, 8),
insn_t(11, 12, 11),
insn_t(5, 1, 14),
insn_t(0, 14, 6),
insn_t(0, 12, 10),
insn_t(24, 14, 16),
insn_t(9, 10, 13),
insn_t(5, 1, 14),
insn_t(0, 14, 7),
insn_t(13, 12, 12),
insn_t(24, 14, 24),
insn_t(5, 1, 14),
insn_t(21, 2, 0),
insn_t(20, 13, 13),
insn_t(0, 14, 8),
insn_t(24, 14, 0),
insn_t(19, 10, 11),
insn_t(5, 2, 14),
insn_t(6, 12, 10),
insn_t(0, 14, 9),
insn_t(8, 11, 11),
insn_t(24, 14, 8),
insn_t(5, 2, 14),
insn_t(0, 14, 10),
insn_t(4, 11, 12),
insn_t(24, 14, 16),
insn_t(5, 2, 14),
insn_t(0, 14, 11),
insn_t(24, 14, 24),
insn_t(4, 13, 12),
insn_t(5, 2, 14),
insn_t(21, 3, 0),
insn_t(0, 14, 12),
insn_t(13, 10, 11),
insn_t(24, 14, 0),
insn_t(16, 10, 10),
insn_t(5, 3, 14),
insn_t(5, 11, 12),
insn_t(0, 14, 13),
insn_t(12, 10, 13),
insn_t(24, 14, 8),
insn_t(2, 10, 13),
insn_t(5, 3, 14),
insn_t(20, 11, 11),
insn_t(0, 14, 14),
insn_t(24, 14, 16),
insn_t(18, 13, 11),
insn_t(5, 3, 14),
insn_t(6, 11, 13),
insn_t(0, 14, 15),
insn_t(24, 14, 24),
insn_t(4, 11, 10),
insn_t(5, 3, 14),
insn_t(21, 4, 0),
insn_t(0, 14, 16),
insn_t(6, 10, 10),
insn_t(24, 14, 0),
insn_t(5, 4, 14),
insn_t(0, 14, 17),
insn_t(12, 13, 13),
insn_t(24, 14, 8),
insn_t(19, 11, 10),
insn_t(5, 4, 14),
insn_t(0, 14, 18),
insn_t(17, 13, 12),
insn_t(24, 14, 16),
insn_t(5, 4, 14),
insn_t(0, 14, 19),
insn_t(24, 14, 24),
insn_t(21, 12, 10),
insn_t(5, 4, 14),
insn_t(13, 13, 10),
insn_t(21, 5, 0),
insn_t(0, 14, 20),
insn_t(19, 10, 13),
insn_t(24, 14, 0),
insn_t(5, 5, 14),
insn_t(0, 14, 21),
insn_t(24, 14, 8),
insn_t(8, 13, 13),
insn_t(5, 5, 14),
insn_t(0, 14, 22),
insn_t(16, 13, 11),
insn_t(24, 14, 16),
insn_t(10, 10, 13),
insn_t(5, 5, 14),
insn_t(7, 10, 12),
insn_t(0, 14, 23),
insn_t(19, 13, 10),
insn_t(24, 14, 24),
insn_t(5, 5, 14),
insn_t(17, 12, 10),
insn_t(21, 6, 0),
insn_t(16, 11, 10),
insn_t(0, 14, 24),
insn_t(24, 14, 0),
insn_t(10, 11, 10),
insn_t(5, 6, 14),
insn_t(0, 14, 25),
insn_t(24, 14, 8),
insn_t(7, 10, 12),
insn_t(5, 6, 14),
insn_t(0, 14, 26),
insn_t(16, 12, 11),
insn_t(24, 14, 16),
insn_t(3, 11, 10),
insn_t(5, 6, 14),
insn_t(0, 14, 27),
insn_t(4, 12, 13),
insn_t(24, 14, 24),
insn_t(5, 6, 14),
insn_t(21, 7, 0),
insn_t(0, 14, 28),
insn_t(21, 13, 11),
insn_t(24, 14, 0),
insn_t(7, 12, 11),
insn_t(5, 7, 14),
insn_t(17, 11, 10),
insn_t(0, 14, 29),
insn_t(24, 14, 8),
insn_t(5, 7, 14),
insn_t(0, 14, 30),
insn_t(12, 10, 10),
insn_t(24, 14, 16),
insn_t(5, 7, 14),
insn_t(0, 14, 31),
insn_t(20, 10, 10),
insn_t(24, 14, 24),
insn_t(5, 7, 14),
insn_t(21, 8, 0),
insn_t(18, 10, 12),
insn_t(0, 14, 32),
insn_t(9, 11, 11),
insn_t(24, 14, 0),
insn_t(21, 12, 11),
insn_t(5, 8, 14),
insn_t(0, 14, 33),
insn_t(24, 14, 8),
insn_t(19, 10, 13),
insn_t(5, 8, 14),
insn_t(8, 12, 13),
insn_t(0, 14, 34),
insn_t(24, 14, 16),
insn_t(5, 8, 14),
insn_t(8, 10, 10),
insn_t(0, 14, 35),
insn_t(24, 14, 24),
insn_t(21, 13, 10),
insn_t(5, 8, 14),
insn_t(0, 12, 10),
insn_t(21, 9, 0),
insn_t(0, 14, 36),
insn_t(24, 14, 0),
insn_t(5, 9, 14),
insn_t(17, 11, 11),
insn_t(0, 14, 37),
insn_t(24, 14, 8),
insn_t(5, 9, 14),
insn_t(4, 10, 11),
insn_t(0, 14, 38),
insn_t(13, 11, 13),
insn_t(24, 14, 16),
insn_t(5, 9, 14),
insn_t(0, 14, 39),
insn_t(10, 11, 10),
insn_t(24, 14, 24),
insn_t(20, 13, 13),
insn_t(5, 9, 14),
insn_t(6, 12, 11),
insn_t(21, 14, 0),
insn_t(8, 0, 2769503260),
insn_t(10, 0, 997841014),
insn_t(19, 12, 11),
insn_t(2, 0, 4065997671),
insn_t(5, 13, 11),
insn_t(8, 0, 690011675),
insn_t(8, 0, 540576667),
insn_t(2, 0, 1618285201),
insn_t(8, 0, 1123989331),
insn_t(8, 0, 1914950564),
insn_t(8, 0, 4213669998),
insn_t(21, 13, 11),
insn_t(8, 0, 1529621790),
insn_t(10, 0, 865446746),
insn_t(2, 10, 11),
insn_t(8, 0, 449019059),
insn_t(16, 13, 11),
insn_t(8, 0, 906976959),
insn_t(6, 10, 10),
insn_t(8, 0, 892028723),
insn_t(10, 0, 1040131328),
insn_t(2, 0, 3854135066),
insn_t(2, 0, 4133925041),
insn_t(2, 0, 1738396966),
insn_t(2, 12, 12),
insn_t(8, 0, 550277338),
insn_t(10, 0, 1043160697),
insn_t(2, 1, 1176768057),
insn_t(10, 1, 2368952475),
insn_t(8, 12, 11),
insn_t(2, 1, 2826144967),
insn_t(8, 1, 1275301297),
insn_t(10, 1, 2955899422),
insn_t(2, 1, 2241699318),
insn_t(12, 11, 10),
insn_t(8, 1, 537794314),
insn_t(11, 13, 10),
insn_t(8, 1, 473021534),
insn_t(17, 12, 13),
insn_t(8, 1, 2381227371),
insn_t(10, 1, 3973380876),
insn_t(10, 1, 1728990628),
insn_t(6, 11, 13),
insn_t(8, 1, 2974252696),
insn_t(0, 11, 11),
insn_t(8, 1, 1912236055),
insn_t(2, 1, 3620744853),
insn_t(3, 10, 13),
insn_t(2, 1, 2628426447),
insn_t(11, 13, 12),
insn_t(10, 1, 486914414),
insn_t(16, 11, 12),
insn_t(10, 1, 1187047173),
insn_t(14, 12, 11),
insn_t(2, 2, 3103274804),
insn_t(13, 10, 10),
insn_t(8, 2, 3320200805),
insn_t(8, 2, 3846589389),
insn_t(1, 13, 13),
insn_t(2, 2, 2724573159),
insn_t(10, 2, 1483327425),
insn_t(2, 2, 1957985324),
insn_t(10, 2, 1467602691),
insn_t(8, 2, 3142557962),
insn_t(2, 13, 12),
insn_t(2, 2, 2525769395),
insn_t(8, 2, 3681119483),
insn_t(8, 12, 11),
insn_t(10, 2, 1041439413),
insn_t(10, 2, 1042206298),
insn_t(2, 2, 527001246),
insn_t(20, 10, 13),
insn_t(10, 2, 855860613),
insn_t(8, 10, 10),
insn_t(8, 2, 1865979270),
insn_t(1, 13, 10),
insn_t(8, 2, 2752636085),
insn_t(2, 2, 1389650363),
insn_t(10, 2, 2721642985),
insn_t(18, 10, 11),
insn_t(8, 2, 3276518041),
insn_t(2, 2, 1965130376),
insn_t(2, 3, 3557111558),
insn_t(2, 3, 3031574352),
insn_t(16, 12, 10),
insn_t(10, 3, 4226755821),
insn_t(8, 3, 2624879637),
insn_t(8, 3, 1381275708),
insn_t(2, 3, 3310620882),
insn_t(2, 3, 2475591380),
insn_t(8, 3, 405408383),
insn_t(2, 3, 2291319543),
insn_t(0, 12, 12),
insn_t(8, 3, 4144538489),
insn_t(2, 3, 3878256896),
insn_t(6, 11, 10),
insn_t(10, 3, 2243529248),
insn_t(10, 3, 561931268),
insn_t(11, 11, 12),
insn_t(10, 3, 3076955709),
insn_t(18, 12, 13),
insn_t(8, 3, 2019584073),
insn_t(10, 13, 12),
insn_t(8, 3, 1712479912),
insn_t(18, 11, 11),
insn_t(2, 3, 2804447380),
insn_t(17, 10, 10),
insn_t(10, 3, 2957126100),
insn_t(18, 13, 13),
insn_t(8, 3, 1368187437),
insn_t(17, 10, 12),
insn_t(8, 3, 3586129298),
insn_t(10, 4, 1229526732),
insn_t(19, 11, 11),
insn_t(10, 4, 2759768797),
insn_t(1, 10, 13),
insn_t(2, 4, 2112449396),
insn_t(10, 4, 1212917601),
insn_t(2, 4, 1524771736),
insn_t(8, 4, 3146530277),
insn_t(2, 4, 2997906889),
insn_t(16, 12, 10),
insn_t(8, 4, 4135691751),
insn_t(8, 4, 1960868242),
insn_t(6, 12, 12),
insn_t(10, 4, 2775657353),
insn_t(16, 10, 13),
insn_t(8, 4, 1451259226),
insn_t(8, 4, 607382171),
insn_t(13, 13, 13),
insn_t(10, 4, 357643050),
insn_t(2, 4, 2020402776),
insn_t(8, 5, 2408165152),
insn_t(13, 12, 10),
insn_t(2, 5, 806913563),
insn_t(10, 5, 772591592),
insn_t(20, 13, 11),
insn_t(2, 5, 2211018781),
insn_t(10, 5, 2523354879),
insn_t(8, 5, 2549720391),
insn_t(2, 5, 3908178996),
insn_t(2, 5, 1299171929),
insn_t(8, 5, 512513885),
insn_t(10, 5, 2617924552),
insn_t(1, 12, 13),
insn_t(8, 5, 390960442),
insn_t(12, 11, 13),
insn_t(8, 5, 1248271133),
insn_t(8, 5, 2114382155),
insn_t(1, 10, 13),
insn_t(10, 5, 2078863299),
insn_t(20, 12, 12),
insn_t(8, 5, 2857504053),
insn_t(10, 5, 4271947727),
insn_t(2, 6, 2238126367),
insn_t(2, 6, 1544827193),
insn_t(8, 6, 4094800187),
insn_t(2, 6, 3461906189),
insn_t(10, 6, 1812592759),
insn_t(2, 6, 1506702473),
insn_t(8, 6, 536175198),
insn_t(2, 6, 1303821297),
insn_t(8, 6, 715409343),
insn_t(2, 6, 4094566992),
insn_t(2, 6, 1890141105),
insn_t(0, 13, 13),
insn_t(2, 6, 3143319360),
insn_t(10, 7, 696930856),
insn_t(2, 7, 926450200),
insn_t(8, 7, 352056373),
insn_t(20, 13, 11),
insn_t(10, 7, 3857703071),
insn_t(8, 7, 3212660135),
insn_t(5, 12, 10),
insn_t(10, 7, 3854876250),
insn_t(21, 12, 11),
insn_t(8, 7, 3648688720),
insn_t(2, 7, 2732629817),
insn_t(4, 10, 12),
insn_t(10, 7, 2285138643),
insn_t(18, 10, 13),
insn_t(2, 7, 2255852466),
insn_t(2, 7, 2537336944),
insn_t(3, 10, 13),
insn_t(2, 7, 4257606405),
insn_t(10, 8, 3703184638),
insn_t(7, 11, 10),
insn_t(10, 8, 2165056562),
insn_t(8, 8, 2217220568),
insn_t(19, 10, 12),
insn_t(8, 8, 2088084496),
insn_t(8, 8, 443074220),
insn_t(16, 13, 12),
insn_t(10, 8, 1298336973),
insn_t(2, 13, 11),
insn_t(8, 8, 822378456),
insn_t(19, 11, 12),
insn_t(8, 8, 2154711985),
insn_t(0, 11, 12),
insn_t(10, 8, 430757325),
insn_t(2, 12, 10),
insn_t(2, 8, 2521672196),
insn_t(10, 9, 532704100),
insn_t(10, 9, 2519542932),
insn_t(2, 9, 2451309277),
insn_t(2, 9, 3957445476),
insn_t(5, 10, 10),
insn_t(8, 9, 2583554449),
insn_t(10, 9, 1149665327),
insn_t(12, 13, 12),
insn_t(8, 9, 3053959226),
insn_t(0, 10, 10),
insn_t(8, 9, 3693780276),
insn_t(2, 9, 609918789),
insn_t(2, 9, 2778221635),
insn_t(16, 13, 10),
insn_t(8, 9, 3133754553),
insn_t(8, 11, 13),
insn_t(8, 9, 3961507338),
insn_t(2, 9, 1829237263),
insn_t(16, 11, 13),
insn_t(2, 9, 2472519933),
insn_t(6, 12, 12),
insn_t(8, 9, 4061630846),
insn_t(10, 9, 1181684786),
insn_t(13, 10, 11),
insn_t(10, 9, 390349075),
insn_t(8, 9, 2883917626),
insn_t(10, 9, 3733394420),
insn_t(10, 12, 12),
insn_t(2, 9, 3895283827),
insn_t(20, 10, 11),
insn_t(2, 9, 2257053750),
insn_t(10, 9, 2770821931),
insn_t(18, 10, 13),
insn_t(2, 9, 477834410),
insn_t(19, 13, 12),
insn_t(3, 0, 1),
insn_t(12, 12, 12),
insn_t(3, 1, 2),
insn_t(11, 13, 11),
insn_t(3, 2, 3),
insn_t(3, 3, 4),
insn_t(3, 4, 5),
insn_t(1, 13, 13),
insn_t(3, 5, 6),
insn_t(7, 11, 11),
insn_t(3, 6, 7),
insn_t(4, 10, 12),
insn_t(3, 7, 8),
insn_t(18, 12, 12),
insn_t(3, 8, 9),
insn_t(21, 12, 10),
insn_t(3, 9, 10)



s.add(regs[0] == 0x3ee88722 )
s.add(regs[1] == 0xecbdbe2 )
s.add(regs[2] == 0x60b843c4 )
s.add(regs[3] == 0x5da67c7 )
s.add(regs[4] == 0x171ef1e9 )
s.add(regs[5] == 0x52d5b3f7 )
s.add(regs[6] == 0x3ae718c0 )
s.add(regs[7] == 0x8b4aacc2 )
s.add(regs[8] == 0xe5cf78dd)
s.add(regs[9] == 0x4a848edf )
s.add(regs[10] == 0x8f )
s.add(regs[11] == 0x4180000 )
s.add(regs[12] == 0x0  )
s.add(regs[13] == 0xd  )
s.add(regs[14] == 0x0)


if(str(s.check()) == "sat"):
    print("[+] flag : ")
    print(s.model())
else:
    print("unsat")