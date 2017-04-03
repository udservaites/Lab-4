#1
import idautils
import idaapi
import idc

values = [0x242070db, 0xd76aa478, 0xe8c7b756, 0xc1bdceee]


hex_bytes = ["C7 45 EC 78 A4 6A D7", "C7 45 F0 56 B7 C7 E8", "C7 45 F4 DB 70 20 24", "C7 45 F8 EE CE BD C1"]

flag = True
while flag
for h_b in hex_bytes:
    if (idc.FindBinary(MinEA(), SEARCH_DOWN, h_b, 16)) != BADADDR:
        print "MD5 Constants found!"
        flag = False
