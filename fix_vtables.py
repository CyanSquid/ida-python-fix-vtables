import idc
import ida_ida
import idautils

# IDA utility functions

def ida__get_disasm(ea):
    return idc.GetDisasm(ea)

def ida__is_unconditional_jump(ea):
    return ida__get_disasm(ea).startswith("jmp")

def ida__is_return(ea):
    returns = ["ret", "retn"]
    return ida__get_disasm(ea).startswith(tuple(returns))

def ida__is_special(ea):
    returns = ["int", "int1", "int3", "ud2", "align", "db", "dw", "dd" "dq"]
    return ida__get_disasm(ea).startswith(tuple(returns))

def ida__is_control_flow_end(ea):
    if ida__is_special(ea):
        return True
    if ida__is_return(ea):
        return True
    #if ida__is_unconditional_jump(ea):
    #    return True
    return False

def ida__does_address_have_name(ea):
    return bool(len(idc.get_name(ea)))

def ida__get_address_name(ea):
    return idc.get_name(ea)

def ida__get_qword(ea):
    return idc.get_qword(ea)

def ida__prev_head(ea):
    return idc.prev_head(ea)

def ida__next_head(ea):
    return idc.next_head(ea)

def ida__create_inst(ea):
    return idc.create_insn(ea)

def ida__del_items(ea):
    return ida_bytes.del_items(ea)

def make_function(ea):
    idc.create_insn(ea)
    ida_funcs.add_func(ea)

def ida__segments():
    return idautils.Segments()
    
def ida__get_segment_name(ea):
    return idc.get_segm_name(ea)

def ida__get_segm_end(ea):
    return idc.get_segm_end(ea)

def ida__get_rdata_segm():
    for segment in ida__segments():
        if ida__get_segment_name(segment) != ".rdata":
            continue
        return (segment, ida__get_segm_end(segment))

def ida__demangle_name(name):
    return idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))


# program functions

def is_non_templated_vtable(ea):
    name = ida__get_address_name(ea)
    if not name.startswith("??_7"):
        return False
        
    if "?" in name[4:]:
        return False
    
    return True
    
def is_valid_vtable_function(name, disasm):
    if "??" in name:
        return False
        
    if "off_" in name:
        return False
        
    if "??" in disasm:
        return False
        
    if not disasm.startswith("dq offset"):
        return False
        
    return True

def fix_vtable_method(ea):
    disasm = ida__get_disasm(ea)
    
    if not all(sep in disasm for sep in ["_", "+"]):
        return None
    
    FN_ADDR = ida__get_qword(ea)
    to_unmake = ida__prev_head(FN_ADDR)

    if to_unmake == 0:
        return

    ea = FN_ADDR

    first = True
    while True:
        if ida__is_control_flow_end(to_unmake) and not first:
            break
        if ida__does_address_have_name(to_unmake) and not first:
            break
        first = False
        
        ida__del_items(to_unmake)
        to_unmake = ida__next_head(to_unmake)
    make_function(FN_ADDR)

def resolve_unk(ea):
    disasm = ida__get_disasm(ea)

    if "unk_" not in disasm:
        return
    if "+" in disasm:
        return
    make_function(ida__get_qword(ea))

def for_each_method(ea, callback):
    name = ida__get_address_name(ea)
    name = ida__demangle_name(name)
    disasm = ida__get_disasm(ea)

    while is_valid_vtable_function(name, disasm):
        temp = callback(ea)
        ea     = ida__next_head(ea)
        disasm = ida__get_disasm(ea)
        name   = ida__get_address_name(ea)
    return ea

def iterate_vtable_methods(begin, end, callback):
    i = begin
    while i < end:
        if not is_non_templated_vtable(i):
            i += 1
            continue
        temp = i
        i = for_each_method(i, callback)
        if i == temp:
            i += 1

def fix_vtables(begin:int = 0, end:int = 0):
    rdata = ida__get_rdata_segm()
    if end == 0:
        end = rdata[1]
    
    if begin == 0:    
        begin = rdata[0]

    # First pass. Resolve "loc_xyz+123"
    print("First Pass")
    iterate_vtable_methods(begin, end, fix_vtable_method)
  
    # Second pass. Resolve "unk_"
    print("Second Pass")
    iterate_vtable_methods(begin, end, resolve_unk)
