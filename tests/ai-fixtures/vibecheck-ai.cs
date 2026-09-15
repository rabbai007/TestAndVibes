public class F {
  void H() {
    // ruleid: vibecheck-untrusted-input-in-system-prompt-cs
    var m = new SystemChatMessage(Request.Query["persona"]);
  }
  void Ex(dynamic client, object msgs) {
    var resp = client.CompleteChat(msgs);
    // ruleid: vibecheck-llm-output-executed-cs
    Process.Start(resp.Content);
  }
  void Rh(dynamic client, object msgs) {
    var r = client.CompleteChat(msgs);
    // ruleid: vibecheck-llm-output-raw-html-cs
    Html.Raw(r.Content);
  }
}
