"""Makes the "pre-started" download for phones: boots the slim image once in the same
emulator build the APK ships (no hardware acceleration, like a phone), prepares it the way
CoreKit does (root control channel on ttyS1, network, set-up done), then saves the running
state. CoreKit resumes from it, so the first start takes about a minute instead of an hour.

Usage: prestart.py <image.iso> <qemu-prefix> <out-dir> [minutes]
Writes: <image>.state.gz (saved state), <image>-started.ckt (data disk), prestart.json
The device list below must stay identical to desktop/vm.go (start)."""
import gzip, hashlib, json, os, re, shlex, socket, struct, subprocess, sys, threading, time

iso, prefix, out = sys.argv[1], sys.argv[2], sys.argv[3]
minutes = float(sys.argv[4]) if len(sys.argv) > 4 else 300
RAM, CPUS = int(os.environ.get("VMRAM", "2048")), int(os.environ.get("VMCPU", "4"))
W = os.environ.get("VMW", "/tmp/vmps"); os.makedirs(W, exist_ok=True); os.makedirs(out, exist_ok=True)
name = os.path.basename(iso)[:-4]
here = os.path.dirname(os.path.abspath(__file__))
subprocess.run(["bsdtar", "-xf", iso, "-C", W, "kernel", "initrd.img"], check=True)

# data disk from the empty template, exactly as CoreKit makes it
tpl = os.path.join(W, "empty.ckt")
subprocess.run(["python3", os.path.join(here, "mktemplate.py"), tpl, "8"], check=True)
disk = os.path.join(W, "data.img")
with gzip.open(tpl) as g, open(disk, "wb") as f:
    assert g.read(4) == b"CKT1"
    size, = struct.unpack("<Q", g.read(8)); f.truncate(size)
    while True:
        off, n = struct.unpack("<QI", g.read(12))
        if n == 0: break
        f.seek(off); f.write(g.read(n))

P0, P1, P2 = 5700, 5701, 5702
snap = os.path.join(W, "state.snap")
args = shlex.split(prefix) + [
    "-name", "CoreKit-prestart", "-accel", "tcg,thread=multi,tb-size=512",
    "-cpu", "max", "-m", str(RAM), "-smp", str(CPUS),
    "-kernel", f"{W}/kernel", "-initrd", f"{W}/initrd.img",
    "-append", "root=/dev/ram0 androidboot.selinux=permissive console=ttyS0 androidboot.console=ttyS0 SRC= DATA=vda nomodeset quiet",
    "-drive", f"file={iso},media=cdrom,readonly=on",
    "-drive", f"file={disk},format=raw,if=virtio,cache=writeback,discard=unmap,detect-zeroes=unmap",
    "-display", "none", "-vga", "std",
    "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
    "-serial", f"tcp:127.0.0.1:{P0},server=on,wait=off", "-serial", f"tcp:127.0.0.1:{P1},server=on,wait=off",
    "-qmp", f"tcp:127.0.0.1:{P2},server=on,wait=off", "-monitor", "none", "-no-reboot"]
print(" ".join(args), flush=True)
log = os.environ.get("GITHUB_WORKSPACE", "/tmp")
q = subprocess.Popen(args, stdout=open(f"{log}/prestart-qemu.log", "ab"), stderr=subprocess.STDOUT)

class Ser:
    def __init__(s, port, logname):
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
    def tail(s, n=300):
        with s.lock: return bytes(s.buf[-n:]).decode(errors="replace")
    def send(s, c): s.k.sendall(c.encode() + b"\n")
    def run(s, c, wait=120):
        mark = f"__CK{time.time_ns()}_"
        with s.lock: st = len(s.buf)
        s.send(f'{c} ; echo "{mark}""END=$?"')
        end = time.time() + wait
        while time.time() < end:
            with s.lock: t = bytes(s.buf[st:]).decode(errors="replace")
            m = re.search(mark + r"END=(\d+)", t)
            if m: return t[:m.start()].replace("\r", ""), int(m.group(1))
            time.sleep(.5)
        return "[TIMEOUT]", -1

def qmp(cmds):
    k = socket.create_connection(("127.0.0.1", P2)); f = k.makefile("rwb"); f.readline()
    res = []
    for c in [{"execute": "qmp_capabilities"}] + cmds:
        f.write((json.dumps(c) + "\n").encode()); f.flush()
        while True:
            r = json.loads(f.readline())
            if "event" not in r: res.append(r); break
    k.close(); return res

t0 = time.time()
con = Ser(P0, f"{log}/prestart-serial0.log")
while time.time() - t0 < minutes * 60:
    time.sleep(5); con.send("")
    if re.search(r"console:/ [#$] *$", con.tail(200).rstrip("\r\n")): break
print(f"console after {time.time()-t0:.0f}s", flush=True)
con.send("setsid sh -c 'cat /dev/ttyS1 | sh >/dev/ttyS1 2>&1' & clear"); time.sleep(5)
a = Ser(P1, f"{log}/prestart-serial1.log")
last = 0
while True:
    if time.time() - t0 > minutes * 60: sys.exit("Android did not finish starting in time")
    o, _ = a.run("getprop sys.boot_completed", 300)
    if o.strip().endswith("1"): break
    if time.time() - last > 600:
        last = time.time(); o, _ = a.run("uptime; getprop init.svc.zygote", 300)
        print(f"[{(time.time()-t0)/60:.0f} min] still starting: {o.strip()[-200:]}", flush=True)
    time.sleep(20)
boot = time.time() - t0
print(f"BOOT COMPLETED after {boot/60:.1f} min", flush=True)
for c in ["settings put global device_provisioned 1; settings put secure user_setup_complete 1",
          "ip link set wifi_eth up; ip addr add 10.0.2.15/24 dev wifi_eth; ndc network create 100; ndc network interface add 100 wifi_eth; "
          "ndc network route add 100 wifi_eth 10.0.2.0/24; ndc network route add 100 wifi_eth 0.0.0.0/0 10.0.2.2; "
          "ndc resolver setnetdns 100 '' 10.0.2.3; ndc network default set 100; setprop net.dns1 10.0.2.3",
          "sleep 120; sync; echo 3 > /proc/sys/vm/drop_caches; free -m",  # let start-up jobs settle
          "F=$(grep MemFree /proc/meminfo | tr -s ' ' | cut -d' ' -f2); N=$(( F/1024 - 300 )); [ $N -gt 0 ] && dd if=/dev/zero of=/dev/ck_zero bs=1048576 count=$N 2>/dev/null; rm -f /dev/ck_zero; free -m"]:  # free memory full of zeros: a much smaller save
    o, rc = a.run(c, 900); print(f"$ {c[:80]} -> {rc}\n{o.strip()[-600:]}", flush=True)
ts = time.time()
print(qmp([{"execute": "stop"}, {"execute": "migrate", "arguments": {"uri": "file:" + snap}}]), flush=True)
while True:
    st = qmp([{"execute": "query-migrate"}])[-1].get("return", {})
    if st.get("status") in ("completed", "failed", "cancelled"): break
    time.sleep(2)
if st.get("status") != "completed": sys.exit("save failed: " + str(st))
print(f"saved in {time.time()-ts:.0f}s, {os.path.getsize(snap)/1e6:.0f} MB", flush=True)
try: qmp([{"execute": "quit"}])
except Exception: pass  # QEMU closes the connection as it quits
time.sleep(3); q.kill(); q.wait()
subprocess.run(["sudo", "chmod", "-R", "a+rwX", W])  # the emulator ran in a container as another user

# outputs: compressed state + data disk as a template (non-zero 64K blocks, like mktemplate.py)
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""): h.update(b)
    return h.hexdigest()
st_out = os.path.join(out, f"{name}.state.gz")
subprocess.run(["sh", "-c", f"gzip -6 -c '{snap}' > '{st_out}'"], check=True)
ck = os.path.join(out, f"{name}-started.ckt")
BS, zero = 64 << 10, bytes(64 << 10)
with open(disk, "rb") as f, gzip.open(ck, "wb", 6) as g:
    g.write(b"CKT1" + struct.pack("<Q", os.path.getsize(disk)))
    off = 0; run_off = None; run = bytearray()
    while True:
        b = f.read(BS)
        if not b: break
        if b != zero[:len(b)]:
            if run_off is None: run_off = off
            run += b
        elif run_off is not None:
            g.write(struct.pack("<QI", run_off, len(run))); g.write(run); run_off, run = None, bytearray()
        off += len(b)
    if run_off is not None: g.write(struct.pack("<QI", run_off, len(run))); g.write(run)
    g.write(struct.pack("<QI", 0, 0))
qexe = shlex.split(prefix)
qpath = next((x for x in qexe if x.endswith("libqemu.so")), None)
qid = ""
if qpath:
    hostp = qpath.replace("/q/", os.environ.get("QHOST", "/tmp/q") + "/", 1)
    with open(hostp, "rb") as f:
        qid = f"{os.path.getsize(hostp)}-{hashlib.sha256(f.read(1 << 20)).hexdigest()[:16]}"
meta = {"image": name, "ram": RAM, "cpus": CPUS, "qemuId": qid, "bootMinutes": round(boot / 60, 1),
        "state": {"file": os.path.basename(st_out), "sha256": sha(st_out), "size": os.path.getsize(st_out), "raw": os.path.getsize(snap)},
        "disk": {"file": os.path.basename(ck), "sha256": sha(ck), "size": os.path.getsize(ck)}}
json.dump(meta, open(os.path.join(out, "prestart.json"), "w"), indent=1)
print(json.dumps(meta, indent=1), flush=True)

# check: resume a copy (the published files stay untouched) and run a root command
subprocess.run(["cp", "--sparse=always", disk, disk + ".test"], check=True)
os.chmod(disk + ".test", 0o666)
targs = [x.replace(f"file={disk},", f"file={disk}.test,") for x in args] + ["-incoming", "file:" + snap]
tr = time.time()
q = subprocess.Popen(targs, stdout=open(f"{log}/prestart-resume.log", "ab"), stderr=subprocess.STDOUT)
ok = False
for _ in range(900):
    try:
        if qmp([{"execute": "query-status"}])[-1].get("return", {}).get("status") == "running": ok = True; break
    except Exception: pass
    time.sleep(1)
print(f"RESUME: running={ok} after {time.time()-tr:.0f}s", flush=True)
if not ok: q.kill(); sys.exit("resume failed")
a = Ser(P1, f"{log}/prestart-resume1.log")
for c in ["id", "getprop sys.boot_completed; uptime", "pm list packages | wc -l", "ip -4 -o addr show | grep -v ' lo '"]:
    t = time.time(); o, rc = a.run(c, 600); print(f"$ {c} -> {rc} in {time.time()-t:.1f}s: {o.strip()[-300:]}", flush=True)
q.kill()
print(f"resume test total {time.time()-tr:.0f}s", flush=True)
