# IDA Server Run Script
---

请求 `http://127.0.0.1:8000/ida/analysis`, 发送以下两个文件:
```json
PAYLOAD_FILES = {
    "binary": open(TARGET_BINARY, "rb"),    # 目标二进制文件
    "script": open(TARGET_SCRIPT, "rb"),    # 需要执行的 IDA 脚本
}
```
同时, 附带以下参数:
```json
PAYLOAD_DATAS = {
    'arch': 64,             # binary 的位数, 可以是 32 或者 64
    'args': json.dumps([    # 脚本所带的参数, 会传递到 python 脚本中, 通过 idc.ARGV 读取
        "--result",
        "result.json",
    ], ensure_ascii=False),
}
```
当程序退出时, 会自动读取 `result.json` 文件. 请确保所有需要的结果保存在改文件中.

其中, 响应的结构定义如下:
```python
resp = {
    "status_code": <IDA Pro Exit Code>,
    "data": <result.json>
}
```
一个示例的响应结果如下:
```json
{
    'status_code': 0, 
    'data': {
        'code': 0, 
        'data': {
            '.init_proc': [4203912, 4203938], 
            'sub_4025B0': [4203952, 4203964], 
            '.__strcat_chk': [4203968, 4203974]
        }
    }
}
```
