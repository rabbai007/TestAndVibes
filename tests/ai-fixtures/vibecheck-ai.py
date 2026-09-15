from anthropic import Anthropic
from flask import request
import subprocess
client = Anthropic()
def persona():
    # ruleid: vibecheck-untrusted-input-in-system-prompt-py
    client.messages.create(model="m", system=f"You are {request.json['persona']}", messages=[])
def ex():
    resp = client.messages.create(model="m", messages=[])
    # ruleid: vibecheck-llm-output-executed-py
    subprocess.run(resp.content[0].text)
def html():
    r = client.messages.create(model="m", messages=[])
    # ruleid: vibecheck-llm-output-raw-html-py
    return HTMLResponse(r.content[0].text)
