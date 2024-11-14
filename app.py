import os
import time
import json
import hashlib
import tempfile
import subprocess
from typing import Union, Dict, List
from flask import Flask, Response, request

IDA_PATH_32 = "C:\\Program Files\\IDA Pro\\v8.3\\ida.exe"
IDA_PATH_64 = "C:\\Program Files\\IDA Pro\\v8.3\\ida64.exe"

app = Flask(__name__)

def ida_run_script(binary_path: str, script_path: str, workspace: str, arch: int=64, script_args: list=[]) -> int:
    assert os.path.isfile(binary_path), f"Cannot Find Binary File at {binary_path}"
    assert os.path.isfile(script_path), f"Cannot Find IDA Script at {script_path}"
    assert os.path.isdir(workspace)
    IDA_WORKSPACE = os.path.abspath(workspace)
    IDA_PATH:str = {32: IDA_PATH_32, 64: IDA_PATH_64}[arch]
    IDA_SCRIPT:str = os.path.abspath(script_path)
    TARGET_PATH:str = os.path.abspath(binary_path)
    IDA_SCRIPT_ARGS:str = ' '.join([f'"{str(_).strip()}"' for _ in script_args])
    IDA_CMDS = [
        IDA_PATH,
        '-A',           # 匿名模式启动, 即不显示 IDA 的窗口
        '-c',           # 如果有现有的 idb 文件, 清除现有的 idb 文件
        (f'-S"{IDA_SCRIPT}" ' + IDA_SCRIPT_ARGS).strip(),   # 加载脚本. 加载的格式类似于 '-S"script.py" "-arg1" "value1" "-arg2" "value2"'
        TARGET_PATH     # 目标二进制文件
    ]
    # 在工作目录打开 IDA 分析脚本
    # print(IDA_CMDS)
    p = subprocess.Popen(IDA_CMDS, cwd=IDA_WORKSPACE)
    while p.poll() is None:
        time.sleep(0.5)
    time.sleep(1)
    return p.poll()

@app.route("/ida/analysis", methods=["POST"])
def ida_analysis_with_script():
    # Step 1: 解析请求参数
    try:
        TARGET_BINARY_FP = request.files['binary']
        TARGET_SCRIPT_FP = request.files['script']
        TARGET_ARCH = int(request.form['arch'])
        TARGET_SCRIPT_ARGS = json.loads(request.form.get('args', '[]'))
        assert isinstance(TARGET_SCRIPT_ARGS, list)
        assert TARGET_ARCH in {32, 64}
    except Exception as e:
        print(e)
        return Response(status=400, response="错误的请求参数. [binary:<file>, script:<file>, arch:<32, 64>, args: [arg1 arg2 arg3]]")
    # Step 2: 构建构建工作目录
    status_code: int = -1
    result: Union[List, Dict] = {}
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir = os.path.abspath(temp_dir)
        TARGET_BINARY = os.path.join(temp_dir, TARGET_BINARY_FP.filename)
        TARGET_BINARY_FP.save(TARGET_BINARY)
        TARGET_SCRIPT = os.path.join(temp_dir, TARGET_SCRIPT_FP.filename)
        TARGET_SCRIPT_FP.save(TARGET_SCRIPT)
        TARGET_RESULT = os.path.join(temp_dir, "result.json")
        # Step 3: 执行 IDA 分析脚本
        status_code = ida_run_script(
            binary_path=TARGET_BINARY,
            script_path=TARGET_SCRIPT,
            workspace=temp_dir,
            arch=TARGET_ARCH,
            script_args=TARGET_SCRIPT_ARGS
            )
        # Step 4: 执行完毕 收集执行的信息
        if status_code == 0 and os.path.isfile(TARGET_RESULT):
            with open(TARGET_RESULT, 'r') as f:
                result = json.load(f)
    # Step 5: 返回
    resp = {
        "status_code": status_code,
        "data": result
    }
    return Response(json.dumps(resp, ensure_ascii=False, indent=2), status=200, mimetype='application/json')


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
