#2
import idautils
import idaapi
import idc

seg = SegByName(".idata")
for head in Heads(SegStart(seg), SegEnd(seg)):
	gen_xrefs = XrefsTo(head, 0)
	for x in gen_xrefs:
		if Name(head) in ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf", "printf"]:
			print GetFunctionName(x.frm), ":", hex(x.frm), ":", Name(head)
