
import os
import json
import requests

SERVER = "http://127.0.0.1:8000"
TARGET_BINARY = os.path.abspath("example/gcc")
TARGET_SCRIPT = os.path.abspath("example/get_all_functions.py")

PAYLOAD_FILES = {
    "binary": open(TARGET_BINARY, "rb"),
    "script": open(TARGET_SCRIPT, "rb"),
}
PAYLOAD_DATAS = {
    'arch': 64,
    'args': json.dumps([
        "--result",
        "result.json",
    ], ensure_ascii=False),
}

resp = requests.request(
    "POST", 
    url=f"{SERVER}/ida/analysis",
    files=PAYLOAD_FILES,
    data=PAYLOAD_DATAS
    )

print(resp.status_code)
if resp.status_code == 200:
    print(resp.json())
else:
    print(resp.content.decode("UTF-8"))
