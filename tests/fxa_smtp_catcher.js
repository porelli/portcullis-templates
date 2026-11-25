// The SMTP catcher of firefox-sync-fxa's tests (tests/apps/firefox-sync-fxa.sh,
// tests/e2e/prep/firefox-sync-fxa.sh): a small SMTP server run with node in
// the accounts image on the instance's network. CATCHER_TLS=1: it offers
// STARTTLS (/tls/key.pem + cert.pem, a test CA's); else none (a server whose
// STARTTLS was stripped). AUTH PLAIN/LOGIN is checked against CATCHER_USER /
// CATCHER_PASS (environment). It logs CONNECT, EHLO, STARTTLS, every AUTH
// command, "PASSWORD SEEN" when any line (or a base64 word of it) holds the
// password, and each message, saved in /tmp/mail with whether it came over TLS.
const net = require("net"), tls = require("tls"), fs = require("fs");
const U = process.env.CATCHER_USER || "", P = process.env.CATCHER_PASS || "";
const TLS = process.env.CATCHER_TLS === "1";
const ctx = TLS ? tls.createSecureContext({key: fs.readFileSync("/tls/key.pem"), cert: fs.readFileSync("/tls/cert.pem")}) : null;
fs.mkdirSync("/tmp/mail", {recursive: true});
let n = 0;
const seen = line => P && (line.includes(P) || line.split(/[ :]/).some(t => { try { return Buffer.from(t, "base64").toString("latin1").includes(P); } catch (e) { return false; } }));
function session(c, secure) {
  let buf = "", data = false, from = "", rcpt = [], authed = false, step = null, user = "";
  const w = s => c.write(s + "\r\n");
  const check = (u, p) => { authed = u === U && p === P; console.log("AUTH " + (authed ? "ok" : "refused") + " user=" + u + (secure ? " tls" : " plain")); w(authed ? "235 2.7.0 ok" : "535 5.7.8 refused"); };
  const plain = b => { const p = Buffer.from(b, "base64").toString().split("\0"); check(p[1] || "", p[2] || ""); };
  c.on("error", () => {});
  c.on("data", function onData(d) {
    buf += d.toString("latin1");
    for (;;) {
      if (data) {
        const i = buf.indexOf("\r\n.\r\n");
        if (i < 0) return;
        n++;
        fs.writeFileSync("/tmp/mail/" + n + ".eml", "MAIL FROM " + from + "\nRCPT " + rcpt.join(",") + "\nAUTH " + (authed ? "ok" : "none") + "\nTLS " + (secure ? "yes" : "no") + "\n\n" + buf.slice(0, i));
        console.log("MESSAGE " + n + " from=" + from + " rcpt=" + rcpt.join(",") + (secure ? " tls" : " plain"));
        buf = buf.slice(i + 5); data = false; w("250 2.0.0 queued");
        continue;
      }
      const i = buf.indexOf("\r\n");
      if (i < 0) return;
      const line = buf.slice(0, i); buf = buf.slice(i + 2);
      if (seen(line)) console.log("PASSWORD SEEN" + (secure ? " tls" : " plain"));
      if (step === "plain") { step = null; plain(line); continue; }
      if (step === "user") { user = Buffer.from(line, "base64").toString(); step = "pass"; w("334 UGFzc3dvcmQ6"); continue; }
      if (step === "pass") { step = null; check(user, Buffer.from(line, "base64").toString()); continue; }
      const a = line.split(" "), cmd = a[0].toUpperCase(), m = (a[1] || "").toUpperCase();
      if (cmd === "AUTH") console.log("AUTH command " + m + (secure ? " tls" : " plain"));
      if (cmd === "EHLO") { console.log("EHLO" + (secure ? " tls" : " plain")); c.write("250-catcher\r\n" + (TLS && !secure ? "250-STARTTLS\r\n" : "") + "250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n"); }
      else if (cmd === "HELO") w("250 catcher");
      else if (cmd === "STARTTLS" && TLS && !secure) {
        w("220 2.0.0 ready");
        c.removeListener("data", onData);
        console.log("STARTTLS");
        session(new tls.TLSSocket(c, {isServer: true, secureContext: ctx}), true);
        return;
      }
      else if (cmd === "AUTH" && m === "PLAIN") { if (a[2]) plain(a[2]); else { step = "plain"; w("334 "); } }
      else if (cmd === "AUTH" && m === "LOGIN") { if (a[2]) { user = Buffer.from(a[2], "base64").toString(); step = "pass"; w("334 UGFzc3dvcmQ6"); } else { step = "user"; w("334 VXNlcm5hbWU6"); } }
      else if (cmd === "MAIL") { if (U && !authed) w("530 5.7.0 authentication required"); else { from = line.slice(10).trim(); rcpt = []; w("250 ok"); } }
      else if (cmd === "RCPT") { rcpt.push(line.slice(8).trim()); w("250 ok"); }
      else if (cmd === "DATA") { data = true; w("354 go ahead"); }
      else if (cmd === "RSET") { from = ""; rcpt = []; w("250 ok"); }
      else if (cmd === "NOOP") w("250 ok");
      else if (cmd === "QUIT") { w("221 bye"); c.end(); }
      else w("502 5.5.2 not implemented");
    }
  });
}
net.createServer(c => { console.log("CONNECT"); c.write("220 catcher ESMTP\r\n"); session(c, false); })
  .listen(587, "0.0.0.0", () => console.log("catcher listening on 587" + (TLS ? " (STARTTLS)" : " (no STARTTLS)")));
