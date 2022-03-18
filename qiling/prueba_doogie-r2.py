#!/usr/bin/env python3
# 
#
#  qemu-system-i386 -hda rootfs/8086/doogie/doogie.DOS_MBR -S -s -cpu pentium


import sys, binascii, math, struct, string, time
from struct import pack
import os
import sys
import r2pipe


# https://stackoverflow.com/questions/9829578/fast-way-of-counting-non-zero-bits-in-positive-integer
def CountBits(n):
    n = (n & 0x5555555555555555) + ((n & 0xAAAAAAAAAAAAAAAA) >> 1)
    n = (n & 0x3333333333333333) + ((n & 0xCCCCCCCCCCCCCCCC) >> 2)
    n = (n & 0x0F0F0F0F0F0F0F0F) + ((n & 0xF0F0F0F0F0F0F0F0) >> 4)
    n = (n & 0x00FF00FF00FF00FF) + ((n & 0xFF00FF00FF00FF00) >> 8)
    n = (n & 0x0000FFFF0000FFFF) + ((n & 0xFFFF0000FFFF0000) >> 16)
    n = (n & 0x00000000FFFFFFFF) + ((n & 0xFFFFFFFF00000000) >> 32) # This last & isn't strictly necessary.
    return n

def ham(lhs: int, rhs: int):
    return CountBits(lhs^rhs)

def calavghd(bs: bytes, sz: int):
    groups = len(bs) // sz
    hdsum = 0
    seqs = [ bs[i*sz:(i+1)*sz] for i in range(groups)]
    for i in range(groups-1):
        seq1 = seqs[i]
        seq2 = seqs[(i+1)%groups]
        for j in range(sz):
            hdsum += ham(seq1[j], seq2[j])
    return hdsum / groups, hdsum / groups / sz

def calavghdall(bs: bytes, maxsz: int):
    r = []
    for i in range(4, maxsz):# I guess 4 min password size 
        r.append((i, *calavghd(bs, i)))
    r.sort(key=lambda x: x[2])
    return r

# Implmentation for https://trustedsignal.blogspot.com/2015/06/xord-play-normalized-hamming-distance.html
def guess_key_size(orig: bytes, maxsz=20):
    avghd = calavghdall(orig, maxsz)
    gcd12 = math.gcd(avghd[0][0], avghd[1][0])
    gcd13 = math.gcd(avghd[0][0], avghd[2][0])
    gcd23 = math.gcd(avghd[1][0], avghd[2][0])
    if gcd12 != 1:
        if gcd12 == gcd13 and gcd12 == gcd23:
            if gcd12 in [t[0] for t in avghd[:5]]:
                if gcd12 == avghd[0][0] or gcd12 == avghd[0][1]:
                    return gcd12
    return avghd[0][0]

def is_all_printable(bs: bytes):
    for b in bs:
        if chr(b) not in string.printable:
            return False
    return True

def countchar(bs: bytes):
    d = {}
    for ch in bs:
        if ch not in d:
            d[ch] = 0
        d[ch] += 1
    r = [(chr(k), v) for k, v in d.items()]
    r.sort(key=lambda x: x[1], reverse=True)
    return r

def cal_count_for_seqs(seqs: dict):
    seqs_keys={}
    for seq in seqs:
        seqs_keys[seq] = {}
        for ch in range(0x20, 0x7E+1):
            xored = bytes([b^ch for b in seq])
            if not is_all_printable(xored):
                continue
            count = countchar(xored)
            seqs_keys[seq][ch] = count
    return seqs_keys

def search_possible_key(seqs: dict, seqs_keys: dict, max_occur=3):
    keys = set()
    cached = {}
    def _impl(seq_idx: bytes, repeated: int, key: str):
        if seq_idx == len(seqs):
            keys.add(key)
            return
        if repeated not in cached[seq_idx]:
            return
        for ch in cached[seq_idx][repeated]:
            _impl(seq_idx + 1, repeated, key + bytes([ch]))
        return
    for idx, seq in enumerate(seqs):
        cached[idx] = {}
        for ch, count in seqs_keys[seq].items():
            for tp in count[:max_occur]:
                if ord(tp[0]) not in cached[idx]:
                    cached[idx][ord(tp[0])] = []
                cached[idx][ord(tp[0])].append(ch)
    for i in range(0x20, 0x7E+1):
        _impl(0, i, b"")
    return keys

def echo_key(key):
    print(f"Current key: {key}")

def show_once(r2, key):
    klen = len(key)

    r2.cmd("wx %s00 @0x87F4" %  key.hex())

    # r2.cmd("dr eax = %d" % klen) <-- this command fails I don't know why...
    r2.cmd("dxa mov eax, %d" % klen)

    # Partial execution to skip input reading
    r2.cmd("dr eip = 0x801B;dc")
    echo_key(key)
    time.sleep(2)

# In this stage, we show every key.
def third_stage(r2, keys):
    # To setup terminal again, we have to restart the whole program.

    for key in keys:
        # reset 
        r2.cmd("dr eip=0x7c00")
        r2.cmd("dr ecx=0")
        r2.cmd("dr ebx=0")
        r2.cmd("dr edi=0")
        r2.cmd("dr edx= 0x80")
        r2.cmd("dr esi=0;")
        r2.cmd("dr esp=0x6f00")
        r2.cmd("dc")
        
        set_required_datetime(r2)
        show_once(r2, key)


# In this stage, we crack the encrypted buffer.
def second_stage(r2):

    data = r2.cmd("p8 0x49B @ 0x8809")
    data = data.strip()
    data = binascii.a2b_hex(data)

    key_size = guess_key_size(data) # Should be 17
    seqs = []
    for i in range(key_size):
        seq = b""
        j = i
        while j < len(data):
            seq += bytes([data[j]])
            j += key_size
        seqs.append(seq)
    seqs_keys = cal_count_for_seqs(seqs)
    keys = search_possible_key(seqs, seqs_keys)
    return keys


def set_required_datetime(r2):
    # Setting Feburary 06, 1990"
    r2.cmd("dr ecx = 0x9019") # 1990
    r2.cmd("dr edx = 0x0602") # 206
    r2.cmd("dc")

# In this stage, we get the encrypted data which xored with the specific date.
def first_stage(r2):
    r2.cmd("db 0x8161; db 0x8018;db 0x803d;dc")
    # Doogie suggests that the datetime should be 1990-02-06.    
    set_required_datetime(r2)

if __name__ == "__main__":
    r2 =  r2pipe.open("gdb://127.0.0.1:1234", ["-d","-D gdb","-2"])
    r2.cmd("e asm.bits = 16")
    r2.cmd("e dbg.bpinmaps = 0")

    first_stage(r2)
    keys = second_stage(r2)
    for key in keys:
        print(f"Possible key: {key}")
    # The key of this challenge is not unique. The real
    # result depends on the last ascii art.
    print("Going to try every key.")
    time.sleep(3)
    third_stage(r2, keys)
