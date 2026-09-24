import os
from anthropic import Anthropic
client = Anthropic()
def prompts():
    # ruleid: vibecheck-secret-in-llm-prompt-py
    client.messages.create(model="m", system=f"DB url is {os.environ['DATABASE_URL']}", messages=[])
    # ok: vibecheck-secret-in-llm-prompt-py
    client.messages.create(model="m", system="You are a helpful assistant", messages=[])
def calls(oai):
    # ruleid: vibecheck-llm-call-unbounded-py
    oai.chat.completions.create(model="gpt-4o", messages=[])
    # ok: vibecheck-llm-call-unbounded-py
    oai.chat.completions.create(model="gpt-4o", messages=[], max_tokens=500)
