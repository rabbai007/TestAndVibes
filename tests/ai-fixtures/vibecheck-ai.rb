# ruleid: vibecheck-untrusted-input-in-system-prompt-rb
msg = { role: "system", content: "You are #{params[:persona]}" }
def ex(client)
  resp = client.messages.create(model: "m")
  # ruleid: vibecheck-llm-output-executed-rb
  system(resp.content)
end
def html(client)
  r = client.messages.create(model: "m")
  # ruleid: vibecheck-llm-output-raw-html-rb
  raw(r.content)
end
