#2
import idautils
import idaapi
import idc

# called_function = ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf"]
# segment = SegByName(".idata")
# for ref in Heads(SegStart(segment), SegEnd(segment)):
#     xrefs = XrefsTo(r, 0)
#     for refrence in xrefs:
#         if Name(ref) in called_function:
#             print GetFunctionName(refrence.frm), ":", hex(reference.frm), ":", Name(ref)

called_func = ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf"]
segment = SegByName(".idata")
for r in Heads(SegStart(segment), SegEnd(segment)):
    xrefs = XrefsTo(r, 0)
    for ref in xrefs:
        if Name(r) in called_func:
            print GetFunctionName(ref.frm), ":", hex(ref.frm), ":", Name(r)
