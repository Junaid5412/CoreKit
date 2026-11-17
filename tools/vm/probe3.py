"""CI probe 3 (ARM, like a phone): long boot with progress, then save state and resume.
probe3.py <iso> <qemu-prefix> <minutes>"""
import json, os, re, shlex, socket, subprocess, sys, threading, time
iso, prefix, minutes = sys.argv[1], sys.argv[2], float(sys.argv[3])
W = os.environ.get("VMW", "/tmp/vm2"); os.makedirs(W, exist_ok=True)
OUT = os.environ.get("GITHUB_WORKSPACE", "/tmp")
subprocess.run(["bsdtar", "-xf", iso, "-C", W, "kernel", "initrd.img"], check=True)
data = os.path.join(W, "data.img")
subprocess.run(["python3", os.path.join(os.path.dirname(__file__), "mktemplate.py"), W + "/t.ckt", "8"], check=True)
# write disk from template (same as CoreKit)
import gzip, struct
with gzip.open(W + "/t.ckt") as g, open(data, "wb") as f:
    assert g.read(4) == b"CKT1"; size, = struct.unpack("<Q", g.read(8)); f.truncate(size)
    while True:
        off, n = struct.unpack("<QI", g.read(12))
        if n == 0: break
        f.seek(off); f.write(g.read(n))
SNAP = W + "/state.snap"
def launch(tag, incoming=False):
    q = shlex.split(prefix) + ["-accel", "tcg,thread=multi,tb-size=512", "-m", "2048", "-smp", os.environ.get("VMCPU", "4"), "-cpu", "max",
        "-kernel", f"{W}/kernel", "-initrd", f"{W}/initrd.img",
        "-append", "root=/dev/ram0 androidboot.selinux=permissive console=ttyS0 androidboot.console=ttyS0 SRC= DATA=vda nomodeset quiet",
        "-drive", f"file={iso},media=cdrom,readonly=on", "-drive", f"file={data},format=raw,if=virtio,cache=writeback",
        "-display", "none", "-vga", "std", "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
        "-serial", "tcp:127.0.0.1:5600,server=on,wait=off", "-serial", "tcp:127.0.0.1:5601,server=on,wait=off",
        "-qmp", "tcp:127.0.0.1:5603,server=on,wait=off", "-monitor", "none", "-no-reboot"]
    if incoming: q += ["-incoming", "file:" + SNAP]
    print(" ".join(q), flush=True)
    return subprocess.Popen(q, stdout=open(f"{OUT}/qemu-{tag}.log", "ab"), stderr=subprocess.STDOUT)
class Ser:
    def __init__(s, port, logname, echo=True):
        s.echo = echo
        for _ in range(300):
            try: s.k = socket.create_connection(("127.0.0.1", port)); break
            except OSError: time.sleep(.2)
        s.buf = bytearray(); s.lock = threading.Lock(); s.log = open(logname, "ab")
        threading.Thread(target=s.rd, daemon=True).start()
    def rd(s):
        while True:
            try: d = s.k.recv(4096)
            except OSError: break
            if not d: break
            s.log.write(d); s.log.flush()
            with s.lock: s.buf.extend(d)
    def tail(s, n=600):
        with s.lock: return bytes(s.buf[-n:]).decode(errors="replace")
    def send(s, c): s.k.sendall(c.encode() + b"\n")
    def run(s, c, wait=60):
        mark = f"__CK{time.time_ns()}"
        with s.lock: st = len(s.buf)
        s.send(f"{c}; echo {mark}=$?")
        end = time.time() + wait
        while time.time() < end:
            with s.lock: t = bytes(s.buf[st:]).decode(errors="replace")
            m = re.search(mark + r"=(\d+)", t)
            if m:
                body = t[:m.start()].replace("\r", "")
                if s.echo: body = body.split("\n", 1)[-1] if "\n" in body else ""
                return body, int(m.group(1))
            time.sleep(.3)
        return "[TIMEOUT]", -1
def qmp(cmds):
    k = socket.create_connection(("127.0.0.1", 5603)); f = k.makefile("rwb"); f.readline()
    out = []
    for c in [{"execute": "qmp_capabilities"}] + cmds:
        f.write((json.dumps(c) + "\n").encode()); f.flush()
        while True:
            r = json.loads(f.readline())
            if "event" not in r: out.append(r); break
    k.close(); return out
def R(ser, cmd, wait=60):
    t = time.time(); o, rc = ser.run(cmd, wait); print(f"$ {cmd}  -> rc={rc} ({time.time()-t:.1f}s)\n{o.strip()[-1500:]}", flush=True); return o, rc
t0 = time.time(); p = launch("cold")
c = Ser(5600, f"{OUT}/serial-cold.log")
prompt = booted = None; last = 0
while time.time() - t0 < minutes * 60 and p.poll() is None:
    time.sleep(10)
    if not prompt:
        c.send("")
        if re.search(r"console:/ [#$] *$", c.tail(200).rstrip("\r\n")): prompt = time.time() - t0; print(f"prompt {prompt:.0f}s", flush=True)
        continue
    o, _ = c.run("getprop sys.boot_completed", 60)
    if o.strip().endswith("1"): booted = time.time() - t0; print(f"BOOT COMPLETED {booted:.0f}s", flush=True); break
    if time.time() - last > 300:
        last = time.time()
        R(c, "uptime; getprop init.svc.zygote; getprop init.svc.bootanim; top -b -n 1 -m 6 -s cpu 2>/dev/null | tail -8 || top -n 1 | head -14", 120)
print(f"cold boot: prompt={prompt} booted={booted}", flush=True)
if booted:
    c.send("setsid sh -c 'cat /dev/ttyS1 | sh >/dev/ttyS1 2>&1' & clear"); time.sleep(3)
    a = Ser(5601, f"{OUT}/serial1-cold.log", echo=True)
    R(a, "id; echo auto-ok", 60)
    R(a, "ip addr add 10.0.2.15/24 dev wifi_eth; ndc network create 100; ndc network interface add 100 wifi_eth; ndc network route add 100 wifi_eth 10.0.2.0/24; "
         "ndc network route add 100 wifi_eth 0.0.0.0/0 10.0.2.2; ndc resolver setnetdns 100 '' 10.0.2.3; ndc network default set 100", 120)
    R(a, "printf 'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n' | toybox nc -w 15 example.com 80 | head -1", 90)
    R(a, "sync; free -m", 120)
    ts = time.time()
    print(qmp([{"execute": "stop"}, {"execute": "migrate", "arguments": {"uri": "file:" + SNAP}}]), flush=True)
    while True:
        st = qmp([{"execute": "query-migrate"}])[-1].get("return", {})
        if st.get("status") in ("completed", "failed", "cancelled"): print("migrate", st.get("status"), st.get("error-desc", ""), flush=True); break
        time.sleep(1)
    print(f"SAVE took {time.time()-ts:.0f}s, file {os.path.getsize(SNAP)/1e6:.0f} MB", flush=True)
    qmp([{"execute": "quit"}]); time.sleep(3); p.kill()
    subprocess.run(["sh", "-c", f"gzip -1 -c {SNAP} | wc -c; xz -T0 -6 -c {SNAP} | wc -c"])
    tr = time.time(); p = launch("resume", incoming=True)
    for _ in range(600):
        try:
            st = qmp([{"execute": "query-status"}])[-1].get("return", {}).get("status")
            if st == "running": break
        except Exception: pass
        time.sleep(1)
    print(f"RESUMED (running) after {time.time()-tr:.0f}s", flush=True)
    a = Ser(5601, f"{OUT}/serial1-resume.log", echo=True)
    R(a, "id; uptime; echo resumed-ok", 120)
    R(a, "pm list packages | head -3", 300)
    R(a, "printf 'GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n' | toybox nc -w 15 example.com 80 | head -1", 120)
    p.kill()
print("SERIAL TAIL:\n" + open(f"{OUT}/serial-cold.log", "rb").read()[-4000:].decode(errors="replace"), flush=True)
