
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

def get_function_decompilation(func_address) -> str:
    # 获取函数对象
    func = idaapi.get_func(func_address)
    if func is None:
        print("Function not found.")
        return ""
    
    # 使用 Hex-Rays 反编译函数
    try:
        decompiled_code = idaapi.decompile(func_address)
        if decompiled_code:
            return str(decompiled_code)
        else:
            return ""
    except:
        return ""

def get_all_decompilation() -> dict:
    ida_auto.auto_wait()
    ret = {}
    for start_ea in idautils.Functions():
        s = get_function_decompilation(start_ea)
        func_name = ida_name.get_name(start_ea)
        ret[func_name] = s
    return ret

funcs = get_all_decompilation()

with open("ida_all_decompilations.json", "w") as f:
    data = json.dumps(funcs, indent=2, ensure_ascii=False)
    f.write(data)

idc.qexit(0)
