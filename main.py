import os
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Constants
REAL_SANDBOX_ROOT = "/srv/agent-redteam/sandbox-2187e03e88"
ALLOWED_HOSTS = {"example.com", "www.iana.org"}

app = FastAPI()

def check_read_file(path):
    # Normalize path and ensure it starts with the sandbox root
    try:
        # Use abspath to handle ../ and other traversals
        target = os.path.abspath(os.path.join(REAL_SANDBOX_ROOT, path.lstrip("/")))
        if not target.startswith(os.path.abspath(REAL_SANDBOX_ROOT)):
            return False, "sandbox escape"
        if not os.path.isfile(target):
            return False, "not a file"
        return True, target
    except:
        return False, "path error"

@app.post("/check")
async def guardrail(request: Request):
    try:
        body = await request.json()
        tool = body.get("tool")
        args = body.get("arguments", {})
        
        if tool == "read_file":
            ok, info = check_read_file(args.get("path", ""))
            if not ok:
                return JSONResponse({"action": "block", "reason": info})
            with open(info, "r", errors="ignore") as f:
                # Returning the string result directly
                return JSONResponse({"action": "allow", "result": f.read()})
        
        elif tool == "fetch_url":
            # For fetch_url, return result as an object with 'text'
            url = args.get("url", "")
            if not any(host in url for host in ALLOWED_HOSTS):
                return JSONResponse({"action": "block", "reason": "host not allowed"})
            
            import requests
            resp = requests.get(url, allow_redirects=False, timeout=5)
            return JSONResponse({"action": "allow", "result": {"text": resp.text}})
            
        return JSONResponse({"action": "block", "reason": "unknown tool"})
    except Exception as e:
        return JSONResponse({"action": "block", "reason": str(e)})