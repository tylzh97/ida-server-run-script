
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

def get_all_strings():
    ret = []
    string: idautils.Strings.StringItem
    for string in idautils.Strings():
        address = string.ea
        length = string.length
        content = str(string)
        s = {
            "address": address,
            "length": length,
            "content": content,
        }
        ret.append(s)
    return ret


all_strings = get_all_strings()

with open("ida_all_strings.json", "w") as f:
    data = json.dumps(all_strings, indent=2, ensure_ascii=False)
    f.write(data)

idc.qexit(0)
