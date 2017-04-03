#1
import idautils
import idaapi
import idc

values = [0x242070db, 0xd76aa478, 0xe8c7b756, 0xc1bdceee]
addr = MinEA()

for value in values:
    flag = True
    while flag:
        addr, operand = idc.FindImmediate(addr, SEARCH_DOWN, value)
        if addr != BADADDR:
                print "MD5 constants present"
            # print hex(addr), idc.GetDisasm(addr)
        else:
            flag = False
