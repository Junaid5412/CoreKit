"""CI probe 2: boots an Android-x86 image with CoreKit's planned setup and tests it.
probe2.py <iso> <qemu-launch-prefix> <accel> <minutes> <apk-to-install>
  qemu-launch-prefix: '' for host qemu, or e.g. 'docker exec tx env LD_LIBRARY_PATH=/q/out /q/out/libqemu.so -L /q/share'
Serial ttyS0 = console (root shell), ttyS1 = automation shell; both on TCP."""
import os, re, shlex, socket, subprocess, sys, threading, time
iso, prefix, accel, minutes, apk = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4]), sys.argv[5]
W = os.environ.get("VMW", "/tmp/vm2"); os.makedirs(W, exist_ok=True)
subprocess.run(["bsdtar", "-xf", iso, "-C", W, "kernel", "initrd.img"], check=True)
data = os.path.join(W, "data.img")
if not os.path.exists(data):
    with open(data, "wb") as f: f.truncate(8 << 30)
    subprocess.run(["mkfs.ext4", "-F", "-q", "-L", "data", "-O", "^orphan_file,^metadata_csum_seed", data], check=True)
def launch(port0, port1, ql):
    q = (shlex.split(prefix) if prefix else ["qemu-system-x86_64"]) + [
        "-accel", accel, "-m", os.environ.get("VMRAM", "2048"), "-smp", os.environ.get("VMCPU", "2"), "-cpu", "max" if accel.startswith("tcg") else "host",
        "-kernel", f"{W}/kernel", "-initrd", f"{W}/initrd.img",
        "-append", "root=/dev/ram0 androidboot.selinux=permissive console=ttyS0 androidboot.console=ttyS0 SRC= DATA=vda nomodeset quiet",
        "-drive", f"file={iso},media=cdrom,readonly=on", "-drive", f"file={data},format=raw,if=virtio",
        "-display", "none", "-vga", "std", "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
        "-serial", f"tcp:127.0.0.1:{port0},server=on,wait=off", "-serial", f"tcp:127.0.0.1:{port1},server=on,wait=off",
        "-monitor", "none", "-no-reboot"]
    print(" ".join(q), flush=True)
    p = subprocess.Popen(q, stdout=open(ql, "ab"), stderr=subprocess.STDOUT); return p
class Ser:
    def __init__(s, port, logname):
        for _ in range(100):
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
    def run(s, c, wait=20):
        mark = f"__CK{time.time_ns()}"
        with s.lock: st = len(s.buf)
        s.send(f"{c}; echo {mark}=$?")
        end = time.time() + wait
        while time.time() < end:
            with s.lock: t = bytes(s.buf[st:]).decode(errors="replace")
            m = re.search(mark + r"=(\d+)", t)
            if m: return t[:m.start()].split("\n", 1)[-1] if "\n" in t[:m.start()] else "", int(m.group(1))
            time.sleep(.25)
        with s.lock: return bytes(s.buf[st:]).decode(errors="replace") + " [TIMEOUT]", -1
OUT = os.environ.get("GITHUB_WORKSPACE", "/tmp")
def boot(tag):
    t0 = time.time()
    p = launch(5600, 5601, f"{OUT}/qemu-{tag}.log")
    c = Ser(5600, f"{OUT}/serial-{tag}.log")
    prompt = booted = None
    while time.time() - t0 < minutes * 60 and p.poll() is None:
        time.sleep(4); c.send("")
        if not prompt and re.search(r"console:/ [#$] *$", c.tail(200).rstrip("\r\n")):
            prompt = time.time() - t0; print(f"[{tag}] prompt {prompt:.0f}s", flush=True)
        if prompt:
            o, _ = c.run("getprop sys.boot_completed", 8)
            if o.strip().endswith("1"): booted = time.time() - t0; print(f"[{tag}] BOOT COMPLETED {booted:.0f}s", flush=True); break
    return p, c, prompt, booted
p, c, pr, bt = boot("first")
def R(cmd, wait=30, ser=None):
    o, rc = (ser or c).run(cmd, wait); print(f"$ {cmd}  -> rc={rc}\n{o.strip()[-1500:]}", flush=True); return o, rc
if bt:
    R("mount | grep -E ' /data '"); R("df -h /data"); R("echo persist-ok > /data/ck_marker; sync; cat /data/ck_marker")
    R("ip addr show eth0; ip route; getprop net.dns1")
    R("ping -c1 -W2 10.0.2.2; ping -c1 -W3 8.8.8.8", 15)
    # automation shell on ttyS1
    c.send("setsid sh -c 'stty -F /dev/ttyS1 raw -echo; exec sh </dev/ttyS1 >/dev/ttyS1 2>&1' &")
    time.sleep(2); a = Ser(5601, f"{OUT}/serial1-first.log"); R("id; echo auto-ok", 10, a)
    # file transfer host -> guest with toybox nc
    data = open(apk, "rb").read()
    srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(("127.0.0.1", 0)); srv.listen(1); port = srv.getsockname()[1]
    def serve():
        k, _ = srv.accept(); k.sendall(data); k.shutdown(socket.SHUT_WR); k.close()
    threading.Thread(target=serve, daemon=True).start()
    R(f"toybox nc 10.0.2.2 {port} </dev/null > /data/local/tmp/t.apk; ls -l /data/local/tmp/t.apk; echo want {len(data)}", 60, a)
    R("pm install -r /data/local/tmp/t.apk", 120, a)
    R("pm list packages -3", 20, a)
    R("cat /system/bin/enable_nativebridge | grep -iE 'http|houdini' | head -20", 10, a)
    R("ls /system/lib/arm /system/lib64/arm64 2>&1 | head; getprop ro.dalvik.vm.native.bridge; getprop persist.sys.nativebridge", 10, a)
    R("free -m; uptime", 10, a)
    R("reboot -p", 5, a); time.sleep(8)
p.kill(); p.wait()
print(f"first boot: prompt={pr} booted={bt}", flush=True)
if bt:
    p, c, pr2, bt2 = boot("second")
    if bt2: R("cat /data/ck_marker; pm list packages -3")
    p.kill()
    print(f"second boot: prompt={pr2} booted={bt2}", flush=True)
