"""End-to-end test of CoreKit's Virtual Environment engine through its HTTP API (CI).
e2e.py <base-url ending in /> [header-value-for-X-CK]"""
import json, sys, time, urllib.request
base = sys.argv[1]; tok = sys.argv[2] if len(sys.argv) > 2 else ""
def call(path, body=None):
    req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), method="GET" if body is None else "POST")
    req.add_header("Content-Type", "application/json")
    if tok: req.add_header("X-CK", tok)
    with urllib.request.urlopen(req, timeout=120) as r: return json.loads(r.read() or b"{}")
def cmd(t, **k):
    try: return call("cmd", dict(t=t, **k))
    except urllib.error.HTTPError as e: sys.exit(f"{t} failed: {e.read()[:300]}")
def wait(desc, fn, mins):
    t0 = time.time(); last = ""
    while time.time() - t0 < mins * 60:
        st = call("state"); v = fn(st)
        if v: print(f"OK {desc} after {time.time()-t0:.0f}s", flush=True); return st
        s = json.dumps([m.get("state") + ":" + str(m.get("detail")) for m in st["machines"]] + [str(i.get("dl")) for i in st["images"]])
        if s != last: print("  ", s[:300], flush=True); last = s
        time.sleep(3)
    sys.exit(f"TIMEOUT waiting for {desc}")
st = call("state"); print(json.dumps(st["host"]), json.dumps(st["images"]), flush=True)
img = st["images"][0]["id"]
if not st["images"][0]["have"]:
    cmd("download", image=img)
    wait("download", lambda s: s["images"][0]["have"] or (s["images"][0].get("dl") or {}).get("state") == "error" and sys.exit(str(s["images"][0]["dl"])), 40)
mid = cmd("create", image=img, name="CI phone")["id"]
m = [x for x in call("state")["machines"] if x["id"] == mid][0]; print("created", m, flush=True)
def mach(s): return [x for x in s["machines"] if x["id"] == mid][0]
cmd("start", id=mid)
wait("running (first start)", lambda s: mach(s)["state"] == "running", 90)
def term_has(text, mins=5):
    since = 0; buf = ""; t0 = time.time()
    while time.time() - t0 < mins * 60:
        r = call(f"term?id={mid}&since={since}"); buf += r.get("t", ""); since = r["n"]
        if text in buf: return True
        time.sleep(1)
    print(buf[-1500:]); return False
cmd("input", id=mid, s="id\r"); print("root console:", term_has("uid=0(root)"), flush=True)
cmd("input", id=mid, s="uptime; date; ps -A | grep -E 'system_server|zygote|surfaceflinger'; service check activity; service check package; logcat -d -b crash | tail -15; echo DIAG-DONE\r")
term_has("DIAG-DONE\n", 3)
r = call(f"term?id={mid}&since=0"); print("---- console ----\n" + r.get("t", "")[-4000:], flush=True)
print("apps:", cmd("apps", id=mid), flush=True)
import os
if os.environ.get("APK"):
    j = cmd("install", id=mid, files=[os.environ["APK"]], label="CK Test")["job"]
    wait("install job", lambda s: any(x["id"] == j and x["state"] != "running" for x in s["jobs"]), 20)
    print("install job:", [x for x in call("state")["jobs"] if x["id"] == j], flush=True)
    print("apps after install:", cmd("apps", id=mid), flush=True)
    print("launch:", cmd("launch", id=mid, pkg="ck.test"), flush=True)
j = cmd("arm", id=mid)["job"]
wait("ARM support job", lambda s: any(x["id"] == j and x["state"] != "running" for x in s["jobs"]) or (print("   arm:", [x["detail"] for x in s["jobs"] if x["id"] == j]) and False), 40)
print("arm job:", [x for x in call("state")["jobs"] if x["id"] == j], flush=True)
t = time.time(); cmd("suspend", id=mid)
wait("saved", lambda s: mach(s)["state"] == "off", 20); print("saved:", mach(call("state")).get("saved"), mach(call("state")).get("savedSize"), flush=True)
t = time.time(); cmd("start", id=mid)
wait("running (resume)", lambda s: mach(s)["state"] == "running", 20)
cmd("input", id=mid, s="echo resumed-ok-$((6*7))\r"); print("console after resume:", term_has("resumed-ok-42"), flush=True)
cmd("stop", id=mid)
wait("shut down", lambda s: mach(s)["state"] == "off", 10)
print("E2E PASSED", flush=True)
