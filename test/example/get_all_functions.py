import os
import time
import json
import argparse

# IDA Pro Libs
import idc
import ida_auto
import idautils
import ida_name
import ida_funcs

##############################################################

parser = argparse.ArgumentParser(description="IDA Script Parser")
parser.add_argument("--result", type=str)
args, unknown = parser.parse_known_args(idc.ARGV[1:])

if not args.result:
    idc.exit(1)
RESULT_FILE = args.result

def get_all_functions() -> dict:
    ida_auto.auto_wait()
    ret = {}
    for start_ea in idautils.Functions():
        end_ea = ida_funcs.get_func(start_ea).end_ea
        func_name = ida_name.get_name(start_ea)
        ret[func_name] = [start_ea, end_ea]
    return ret

with open(RESULT_FILE, "w", encoding="UTF-8") as f:
    result = {
        "code": 0,
        "data": get_all_functions()
    }
    f.write(json.dumps(result, ensure_ascii=False, indent=2))

idc.qexit(0)
exit(0)
