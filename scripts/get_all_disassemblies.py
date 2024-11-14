
# 导入系统依赖
import os
import time
import json
# 导入 IDA 依赖
import idc
import idaapi
import ida_auto
import idautils
import ida_name
import ida_funcs

def get_function_disassembly(func_address) -> str:
    # 获取函数对象
    func = idaapi.get_func(func_address)
    if func is None:
        print("Function not found.")
        return ""
    
    # 获取函数的起始和结束地址
    start = func.start_ea
    end = func.end_ea
    
    # 遍历指令并打印反汇编代码
    disassembly = []
    for addr in range(start, end):
        if idc.is_code(idc.get_full_flags(addr)):
            disasm = idc.generate_disasm_line(addr, 0)
            disassembly.append(disasm)
    
    return "\n".join(disassembly)

def get_all_decompilation() -> dict:
    ida_auto.auto_wait()
    ret = {}
    for start_ea in idautils.Functions():
        s = get_function_disassembly(start_ea)
        func_name = ida_name.get_name(start_ea)
        ret[func_name] = s
    return ret

funcs = get_all_decompilation()

with open("ida_all_disassembly.json", "w") as f:
    data = json.dumps(funcs, indent=2, ensure_ascii=False)
    f.write(data)

idc.qexit(0)
