public class F {
  void h(javax.servlet.http.HttpServletRequest req) {
    // ruleid: vibecheck-untrusted-input-in-system-prompt-java
    SystemMessage.from(req.getParameter("persona"));
  }
  void ex(Client client, Object params) throws Exception {
    var resp = client.messages().create(params);
    // ruleid: vibecheck-llm-output-executed-java
    Runtime.getRuntime().exec(resp.content());
  }
}
