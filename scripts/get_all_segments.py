
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
import ida_segment

def get_all_segments() -> dict:
    ida_auto.auto_wait()
    ret = {}
    for start_ea in idautils.Segments():
        segment = idaapi.getseg(start_ea)
        segname = idc.get_segm_name(segment.start_ea)
        ret[segname] = [segment.start_ea, segment.end_ea]
    return ret


with open("ida_all_segments.json", "w") as f:
    segs = get_all_segments()
    data = json.dumps(segs, indent=2, ensure_ascii=False)
    f.write(data)

idc.qexit(0)
