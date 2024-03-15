from qiling import Qiling
from qiling.const import QL_VERBOSE
from pwn import *
import base64


def find_stack_value():
    ql = Qiling([r'/home/kali/Bureau/CTF/htb_battle/QuickScan/test.bin'], r'/home/kali/Bureau/CTF/htb_battle/QuickScan/res')
    ql.run()

    solution=""
    offset=0
    peek_diff=True
    while peek_diff:
        stack_peek = hex(ql.arch.stack_read(offset))[2:]

        if len(stack_peek) ==16: # is 8 byte aligned
            stack_val = bytearray.fromhex(stack_peek)
            stack_val.reverse()
            solution+=stack_val.hex()

        elif len(stack_peek) == 15: # missing the zero
            stack_val = bytearray.fromhex("0"+stack_peek)
            stack_val.reverse()
            solution+=stack_val.hex()
        else:
            peek_diff=False
        offset+=8
    print("SOLUTION: ", solution)
    return solution


def retrieve_remote_binary():
    r = remote("94.237.62.237", 56854)
    problem_intro = r.recvuntil(b'ELF:  ')
    while b"ELF"  in problem_intro:

        binary_b64 = r.recvuntil(b'\n')[:-1]
        decoded_val = base64.b64decode(binary_b64)
        f = open('/home/kali/Bureau/CTF/htb_battle/QuickScan/test.bin','wb')
        f.write(decoded_val)
        f.close()
        solution_stack_val =find_stack_value()
        r.sendlineafter(b'Bytes?', solution_stack_val.encode())
        #sleep()
        try:
            problem_intro = r.recvuntil(b'ELF:  ')
        except:
            r.interactive()
    





retrieve_remote_binary()

#  HTB{y0u_4n4lyz3d_th3_p4tt3ns!}
