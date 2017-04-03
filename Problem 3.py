#3
import idautils
import idaapi
import idc

export_functions = []

#search recursively to get all the function calls
def search(head, export):
    if GetFunctionName(head) in export_functions:
        print GetFunctionName(head), " : ", export
    else:
        for reference in XrefsTo(head, 0):
            if GetFunctionName(reference.frm) is not Name(head):
                search(reference.frm, export)
                return

#Look for an import funciton for each export function
for i in range(GetEntryPointQty()):
    ord = GetEntryOrdinal(i)
    if ord == 0:
        continue
    addr = GetEntryPoint(ord)
    export_functions.append(GetFunctionName(addr))


ea = ScreenEA()
#functions to search
called_function = ["strcpy", "sprintf", "strncpy", "wcsncpy", "swprintf"]
for function in Functions(SegStart(ea),SegEnd(ea)):
    start = GetFunctionAttr(function, FUNCATTR_START)
    end = GetFunctionAttr(function, FUNCATTR_END)
    for head in Heads(start, end):
        if isCode(GetFlags(head)):
            for word in GetDisasm(head).split():
                if word in called_function:
                    search(head, word)
