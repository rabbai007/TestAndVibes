import re
import requests
from flask import request
def build():
    pat = request.args.get("pattern")
    # ruleid: vibecheck-user-controlled-regex-py
    rx = re.compile(pat)
    # ok: vibecheck-user-controlled-regex-py
    ok = re.compile(r"^[a-z0-9]+$")
    return rx, ok
def unpack(z):
    # ruleid: vibecheck-archive-extractall-unbounded
    z.extractall("/tmp/out")
def fetch():
    # ruleid: vibecheck-outbound-request-no-timeout-py
    requests.get("https://api.example.com/data")
    # ok: vibecheck-outbound-request-no-timeout-py
    requests.get("https://api.example.com/data", timeout=(3, 10))
