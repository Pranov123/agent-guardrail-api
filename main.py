import os
import re
from urllib.parse import urlparse
import requests
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Constants
REAL_SANDBOX_ROOT = "/srv/agent-redteam/sandbox-2187e03e88"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

app = FastAPI()

def check_read_file(path):
    try:
        # Use realpath to resolve /../ and other bypasses
        target = os.path.realpath(os.path.join(REAL_SANDBOX_ROOT, path))
        if not target.startswith(os.path.realpath(REAL_SANDBOX_ROOT)):
            return False, "sandbox escape"
        if not os.path.isfile(target):
            return False, "not a file"
        return True, target
    except: return False, "path error"

def is_safe_url(url):
    try:
        parsed = urlparse(url)
        # 1. Enforce HTTPS
        if parsed.scheme != "https": return False, "only https"
        # 2. Strict Host Whitelist
        if parsed.hostname not in ALLOWED_HOSTS: return False, "host not allowed"
        # 3. Block userinfo (e.g., https://user:pass@example.com)
        if parsed.username or parsed.password: return False, "userinfo not allowed"
        return True, "ok"
    except: return False, "malformed url"

@app.post("/check")
async def guardrail(request: Request):
    try:
        body = await request.json()
        tool, args = body.get("tool"), body.get("arguments", {})
        
        if tool == "read_file":
            ok, info = check_read_file(args.get("path", ""))
            if not ok: return JSONResponse({"action": "block", "reason": info})
            with open(info, "r", errors="ignore") as f:
                return JSONResponse({"action": "allow", "result": {"content": f.read()}})
        
        elif tool == "fetch_url":
            url = args.get("url", "")
            ok, reason = is_safe_url(url)
            if not ok: return JSONResponse({"action": "block", "reason": reason})
            
            # Use allow_redirects=False to prevent SSRF redirect-to-private
            resp = requests.get(url, allow_redirects=False, timeout=5)
            if resp.is_redirect: return JSONResponse({"action": "block", "reason": "redirects forbidden"})
            
            return JSONResponse({"action": "allow", "result": {"text": resp.text}})
            
        return JSONResponse({"action": "block", "reason": "unknown tool"})
    except Exception as e:
        return JSONResponse({"action": "block", "reason": str(e)})