import idautils

call_chain = [] # store calling relationships

def gen_call_chain(func_name, osintneting):
    del call_chain[:]

    f_call_out = open('/Users/mac/Desktop/idaXrefFrom.txt', 'w')
    
    get_my_callee(func_name, osintneting, f_call_out)
    
    f_call_out.close()
    
def get_my_callee(func_name, osintneting, fl):
    #print('call %s %d' % (func_name, osintneting))
    
    if ida_kernwin.user_cancelled():
    
        print('Cancelled')
    
        fl.close()
    
        exit()
    
    str = '{0}\t'.format(func_name)
    
    call_chain.append(str)
    
    addr = get_name_ea(0, func_name)
    
    # get all sub functions
    
    dism_addr = list(idautils.FuncItems(addr))
    
    xref_froms = []
    
    for ea in dism_addr:
    
        if ida_idp.is_call_insn(ea) is False:
    
            continue
    
        else:
    
            callee = get_first_fcref_from(ea)
    
            if callee != addr:
    
                xref_froms.append(callee)
    
    xref_froms = set(xref_froms)
    

    
    osinteneting_end = False
    
    if len(xref_froms) == 0:
    
        osinteneting_end = True
    
    elif osintneting == -1:
    
        osinteneting_end = False
    
    elif osintneting == 1:
    
        osinteneting_end = True
    
    if osinteneting_end is True:
    
        for callee in call_chain:
    
            sys.stdout.write(callee)
    
            fl.write(callee)
    
        sys.stdout.write('\r\n')
    
        fl.write('\r\n')
    
        call_chain.pop()
    
        return

    
    for xref_from in xref_froms:
    
        callee_name = get_func_name(xref_from)
    
        if osintneting == -1:
    
            get_my_callee(callee_name, -1, fl)
    
        else:
    
            get_my_callee(callee_name, osintneting - 1, fl)
    
    call_chain.pop()
