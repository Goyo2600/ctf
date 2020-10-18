#!/usr/bin/python3
import subprocess
import r2pipe
import random
import phoenixAES

# aesthetic challenge :: r2con2020 :: goyo ::
# AES crack using DFA. ::  There are more ways than ESIL.. :: 
# Unboxing the White-Box Practical attacks against Obfuscated Ciphers
# https://www.blackhat.com/docs/eu-15/materials/eu-15-Sanfelix-Unboxing-The-White-Box-Practical-Attacks-Against-Obfuscated-Ciphers-wp.pdf

# first blood:
# https://github.com/BlackVS/CTFs/tree/master/r2con2020/tasks/aesthetic
# Extract data from binary for generating inverse functions and finally the aes key.

def crack(f):
    return phoenixAES.crack_file(f,outputbeforelastrounds=False, verbose=0)

def round():
    r2p = r2pipe.open("./whitebox",flags=["-2"])
    r2p.cmd("aa;doo 74657374746573747465737474657374")
    r2p.cmd("dcu main")

    r2p.cmd("s sym.aes_128_table_encrypt + 0x944;db $$")
    # round 9
    r2p.cmd("8 dc")
    # modify a byte in rount 9 with random value 0-255, DFA attack (view pdf) 
    command = "wx %02x @[rsp+0xe0]+0x%02x" % (random.randint(0,255),random.randint(0,15))
    r2p.cmd(command)
    r2p.cmd("dc")
    r2p.cmd("dcr")

    ret = r2p.cmd("p8 0x10 @ rsi")
    r2p.quit()
    return ret.rstrip('\n')


f = open("tracefile","w")
# ./whitebox 74657374746573747465737474657374
# 74657374746573747465737474657374     
# 22631EF63FFA0A2DA77FD13BDF407DB3 <---- first line in tracefile 
f.write("74657374746573747465737474657374 22631EF63FFA0A2DA77FD13BDF407DB3\n")

for i in range(10):# 10 minimum traces
    out = round()
    print("Generating trace %2d: %s" % (i+1,out))
    f.write("74657374746573747465737474657374 %s\n" % out)

f.flush()
r_key=crack("tracefile")
while '..' in r_key: # if no crack possible generate one more trace
    r = round()
    print("Generating trace %2d: %s" % (i+2,r))
    f.write("74657374746573747465737474657374 %s\n" % r)
    f.flush()
    r_key=crack("tracefile")
    i += 1

get_aes_key = subprocess.Popen("Stark/aes_keyschedule %s 10 | grep K00 | xxd -r -p" % r_key,shell=True, stdout=subprocess.PIPE).stdout
aes_key =  get_aes_key.read()
print("flag r2con{%s}\n" % aes_key.decode()) 
f.close()

