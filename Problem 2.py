#2
import idautils
import idaapi
import idc

called_function = ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf"]
segment = SegByName(".idata")
for ref in Heads(SegStart(segment), SegEnd(segment)):
    xrefs = XrefsTo(ref, 0)
    for reference in xrefs:
        if Name(ref) in called_function:
            print GetFunctionName(reference.frm), ":", hex(reference.frm), ":", Name(ref)
