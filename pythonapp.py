import base64
import hashlib
import hmac
import json
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

JWT_SECRET = b"demo-secret-key-change-in-prod"

USERS = {
    "alice": {
        "salt": "s1",
        "pw_hash": hashlib.sha256(b"s1:CorrectPass123").hexdigest(),
        "device_id": "dev-iphone-01",
    }
}

PENDING_OTPS = {}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def issue_jwt(sub: str, device_id: str, ttl_sec: int = 120) -> str:
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64url(
        json.dumps(
            {
                "sub": sub,
                "amr": ["pwd", "oob_otp", "dev"],
                "device_id": device_id,
                "iat": int(time.time()),
                "exp": int(time.time()) + ttl_sec,
            }
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    sig = b64url(hmac.new(JWT_SECRET, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


def verify_jwt(token: str) -> dict:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Malformed JWT")
    header, payload, sig = parts
    expected = b64url(
        hmac.new(JWT_SECRET, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(sig, expected):
        raise ValueError("Invalid JWT signature (tampered!)")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    if time.time() > claims["exp"]:
        raise ValueError("JWT expired")
    return claims


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>3FA + JWT Security Demo</title>
<style>
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }
  .wrap { max-width: 820px; margin: 0 auto; display: grid; gap: 16px; grid-template-columns: 1fr 1fr; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 18px; }
  .full { grid-column: 1 / -1; }
  h1 { margin: 0 0 6px; font-size: 20px; }
  h2 { margin: 0 0 12px; font-size: 15px; color: #93c5fd; }
  label { display: block; font-size: 12px; color: #94a3b8; margin: 10px 0 4px; }
  input, select { width: 100%; box-sizing: border-box; padding: 8px 10px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; }
  button { margin-top: 12px; padding: 9px 14px; border: 0; border-radius: 8px; background: #2563eb; color: white; font-weight: 600; cursor: pointer; }
  button.sec { background: #475569; }
  button.warn { background: #b91c1c; }
  .oob { background: #020617; border: 1px dashed #38bdf8; border-radius: 8px; padding: 10px; font-family: monospace; color: #38bdf8; margin-top: 10px; }
  pre { background: #020617; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 12px; margin: 8px 0 0; }
  .ok { color: #4ade80; } .err { color: #f87171; }
  @media (max-width: 700px) { .wrap { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">
  <div class="card full">
    <h1>Triple-Factor Authentication (3FA) + JWT Demo</h1>
    <div style="font-size:13px;color:#94a3b8;">Project SEC-PRJ-7F_25 — Factor 1 (Password) + Factor 2 (Out-of-Band OTP) + Factor 3 (Trusted Device)</div>
  </div>

  <div class="card">
    <h2>Step 1 — Factor 1: Password</h2>
    <label>Username</label>
    <input id="user" value="alice" />
    <label>Password (valid: CorrectPass123)</label>
    <input id="pass" type="password" value="CorrectPass123" />
    <button onclick="doStep1()">Verify Password & Send OTP</button>

    <div class="oob" id="oobBox">[Simulated Out-of-Band / Social Channel]<br/>Waiting for Step 1...</div>
  </div>

  <div class="card">
    <h2>Step 2 & 3 — OTP + Device Context</h2>
    <label>Factor 2: 6-Digit Out-of-Band OTP</label>
    <input id="otp" placeholder="Enter 6-digit OTP" />
    <label>Factor 3: Device ID</label>
    <select id="dev">
      <option value="dev-iphone-01">dev-iphone-01 (Registered Device)</option>
      <option value="dev-unknown-99">dev-unknown-99 (Attacker Device)</option>
    </select>
    <button onclick="doStep2()">Complete 3FA & Mint JWT</button>
  </div>

  <div class="card full">
    <h2>Result & JWT Verifier</h2>
    <div id="status" style="font-size:14px;font-weight:600;">Ready.</div>
    <label>Issued JWT</label>
    <input id="jwt" placeholder="JWT appears here after all 3 factors pass" />
    <button class="sec" onclick="checkJwt()">Verify JWT</button>
    <button class="warn" onclick="tamperJwt()">Tamper JWT Payload</button>
    <pre id="output">{}</pre>
  </div>
</div>

<script>
async function post(url, data) {
  const res = await fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify(data)
  });
  return res.json();
}

function show(ok, msg, obj) {
  const st = document.getElementById("status");
  st.className = ok ? "ok" : "err";
  st.textContent = msg;
  document.getElementById("output").textContent = JSON.stringify(obj, null, 2);
}

async function doStep1() {
  const r = await post("/step1", {
    username: document.getElementById("user").value,
    password: document.getElementById("pass").value
  });
  if (r.ok) {
    document.getElementById("oobBox").innerHTML =
      `[Simulated Out-of-Band / Social Channel]<br/>OTP for <b>${r.username}</b>: <b>${r.otp}</b> (valid 60s)`;
    document.getElementById("otp").value = r.otp;
    show(true, "Factor 1 passed! OTP sent out-of-band.", r);
  } else {
    show(false, "Factor 1 failed: " + r.error, r);
  }
}

async function doStep2() {
  const r = await post("/step2", {
    username: document.getElementById("user").value,
    otp: document.getElementById("otp").value,
    device_id: document.getElementById("dev").value
  });
  if (r.ok) {
    document.getElementById("jwt").value = r.token;
    show(true, "All 3 factors verified! Signed JWT issued.", r);
  } else {
    show(false, "3FA rejected: " + r.error, r);
  }
}

async function checkJwt() {
  const r = await post("/verify", { token: document.getElementById("jwt").value });
  show(r.ok, r.ok ? "JWT signature & expiry valid!" : "JWT rejected: " + r.error, r);
}

function tamperJwt() {
  const el = document.getElementById("jwt");
  if (!el.value) return;
  const parts = el.value.split(".");
  if (parts.length === 3) {
    parts[1] = parts[1].slice(0, -2) + "AA";
    el.value = parts.join(".");
    show(false, "Modified JWT payload — click 'Verify JWT' to see signature rejection.", { tampered_jwt: el.value });
  }
}
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def send_json(self, code: int, obj: dict):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        body = HTML_PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        data = json.loads(self.rfile.read(length) or b"{}")

        if self.path == "/step1":
            u = data.get("username", "")
            p = data.get("password", "")
            user = USERS.get(u)
            if not user:
                return self.send_json(401, {"ok": False, "error": "Invalid credentials"})
            check = hashlib.sha256(f"{user['salt']}:{p}".encode()).hexdigest()
            if not hmac.compare_digest(check, user["pw_hash"]):
                return self.send_json(401, {"ok": False, "error": "Invalid credentials"})

            otp = f"{secrets.randbelow(1_000_000):06d}"
            PENDING_OTPS[u] = {"code": otp, "expires": time.time() + 60, "used": False}
            return self.send_json(200, {"ok": True, "username": u, "otp": otp})

        if self.path == "/step2":
            u = data.get("username", "")
            otp = data.get("otp", "")
            dev = data.get("device_id", "")
            rec = PENDING_OTPS.get(u)
            if not rec or rec["used"] or time.time() > rec["expires"]:
                return self.send_json(401, {"ok": False, "error": "OTP missing, used, or expired"})
            if not hmac.compare_digest(rec["code"], otp):
                return self.send_json(401, {"ok": False, "error": "Wrong OTP (Factor 2 failed)"})
            user = USERS.get(u)
            if not user or not hmac.compare_digest(user["device_id"], dev):
                return self.send_json(401, {"ok": False, "error": "Untrusted device (Factor 3 failed)"})

            rec["used"] = True
            token = issue_jwt(u, dev)
            return self.send_json(200, {"ok": True, "token": token, "claims": verify_jwt(token)})

        if self.path == "/verify":
            try:
                claims = verify_jwt(data.get("token", ""))
                return self.send_json(200, {"ok": True, "claims": claims})
            except Exception as e:
                return self.send_json(401, {"ok": False, "error": str(e)})

        self.send_json(404, {"ok": False, "error": "Not found"})


if __name__ == "__main__":
    print("Open http://localhost:8000 in your browser")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()