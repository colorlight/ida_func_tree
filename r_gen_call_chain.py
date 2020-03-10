import idautils

r_call_chain = [] # 存放反向调用链信息

def gen_r_call_chain(func_name, osintneting):
    del r_call_chain[:]
    
    f_r_call_out = open('/Users/mac/Desktop/idaXrefTo.txt', 'w')
    
    get_my_caller(func_name, osintneting, f_r_call_out)
    
    f_r_call_out.close()

def get_my_caller(func_name, osintneting, fl):
    if ida_kernwin.user_cancelled():
    
        print('Cancelled')
    
        fl.close()
    
        exit()
    
    str = '{0}\t'.format(func_name)
    
    r_call_chain.append(str)
    
    addr = get_name_ea(0, func_name)
    
    addr_ref_to = get_first_fcref_to(addr)
    
    # 嵌套结束条件 
    
    osinteneting_end = False
    
    if addr_ref_to == BADADDR:
    
        osinteneting_end = True
    
    elif osintneting == -1:
    
        osinteneting_end = False
    
    elif osintneting == 1:
    
        osinteneting_end = True
    
    if osinteneting_end is True:
    
        length = len(r_call_chain)
    
        for idx in range(length):
    
            fl.write(r_call_chain[length - idx - 1])
    
            #sys.stdout.write(r_call_chain[length - idx - 1])
    
        fl.write("\n")
    
       # sys.stdout.write('\r\n')
    
        r_call_chain.pop()
    
        return
    
    # 深度优先
    
    while (addr_ref_to != BADADDR) and (addr_ref_to != addr):
    
        parent_func_name = get_func_name(addr_ref_to)
    
        get_my_caller(parent_func_name, osintneting - 1, fl)
    
        addr_ref_to = get_next_fcref_to(addr, addr_ref_to)
    
        if addr_ref_to == BADADDR:
    
            r_call_chain.pop() # 如果没有引用函数，弹出当前函数
    
            break
