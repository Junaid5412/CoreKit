"""CI probe: boots an Android-x86 ISO headless in QEMU and checks the root shell on the serial
console. Usage: boot_probe.py <iso> <accel kvm|tcg> <minutes> [extra kernel args]"""
import os, re, socket, subprocess, sys, threading, time
iso, accel, minutes = sys.argv[1], sys.argv[2], float(sys.argv[3])
extra = sys.argv[4] if len(sys.argv) > 4 else ""
w = "/tmp/vmp-" + accel; os.makedirs(w, exist_ok=True)
subprocess.run(["bsdtar", "-xf", iso, "-C", w, "kernel", "initrd.img"], check=True)
for f in ["isolinux/isolinux.cfg", "boot/grub/grub.cfg", "efi/boot/android.cfg"]:
    r = subprocess.run(["bsdtar", "-xOf", iso, f], capture_output=True, text=True)
    if r.returncode == 0: print("=====", f); print(r.stdout[:3000])
data = os.path.join(w, "data.img")
with open(data, "wb") as f: f.truncate(4 << 30)
sock = os.path.join(w, "s0")
args = ["qemu-system-x86_64", "-accel", accel, "-m", "2048", "-smp", "2", "-cpu", "max" if accel == "tcg" else "host",
        "-kernel", os.path.join(w, "kernel"), "-initrd", os.path.join(w, "initrd.img"),
        "-append", f"root=/dev/ram0 androidboot.selinux=permissive console=ttyS0 androidboot.console=ttyS0 SRC= DATA= nomodeset {extra}".strip(),
        "-drive", f"file={iso},media=cdrom,readonly=on", "-drive", f"file={data},format=raw,if=virtio",
        "-display", "none", "-vga", "std", "-netdev", "user,id=n0", "-device", "e1000,netdev=n0",
        "-serial", f"unix:{sock},server=on,wait=off", "-monitor", "none", "-no-reboot"]
print(" ".join(args)); t0 = time.time()
q = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
threading.Thread(target=lambda: [print("[qemu]", l.decode(errors="replace").rstrip()) for l in q.stdout], daemon=True).start()
for _ in range(50):
    if os.path.exists(sock): break
    time.sleep(.2)
s = socket.socket(socket.AF_UNIX); s.connect(sock)
buf = bytearray(); lock = threading.Lock()
log = open(os.path.join(os.environ.get("GITHUB_WORKSPACE", "/tmp"), f"serial-{accel}.log"), "wb")
def rd():
    while True:
        d = s.recv(4096)
        if not d: break
        log.write(d); log.flush()
        with lock: buf.extend(d)
threading.Thread(target=rd, daemon=True).start()
def tail(n=4000):
    with lock: return bytes(buf[-n:]).decode(errors="replace")
def send(c): s.sendall(c.encode() + b"\n")
def run(c, wait=8):
    mark = f"__CK{int(time.time()*1000)}"
    with lock: start = len(buf)
    send(f"{c}; echo {mark} $?")
    end = time.time() + wait
    while time.time() < end:
        with lock: t = bytes(buf[start:]).decode(errors="replace")
        m = re.search(mark + r" (\d+)", t.split(f"echo {mark}", 1)[-1])
        if m: return t
        time.sleep(.3)
    with lock: return bytes(buf[start:]).decode(errors="replace") + "  [timeout]"
deadline = t0 + minutes * 60; prompt = None; booted = None
while time.time() < deadline and q.poll() is None:
    time.sleep(5); send("")
    t = tail(600)
    if not prompt and re.search(r"[:/][^\n]*[$#] ?$", t.rstrip("\r\n ") + " ") is not None and ("$ " in t[-60:] or "# " in t[-60:]):
        prompt = time.time() - t0; print(f"PROMPT after {prompt:.0f}s:", repr(t[-200:]))
    if prompt:
        r = run("getprop sys.boot_completed", 6)
        if re.search(r"\n1\r?\n", r):
            booted = time.time() - t0; print(f"BOOT COMPLETED after {booted:.0f}s"); break
print("--- probes ---")
for c in ["id", "su -c id", "su 0 id", "getprop ro.build.version.release", "getprop ro.debuggable", "getprop ro.adb.secure",
          "getprop ro.product.cpu.abilist", "ls /dev/block", "ls /system/bin/mke2fs /system/bin/nc /system/bin/toybox /system/xbin/su /system/bin/su",
          "toybox | head -c 1500", "cat /proc/cmdline", "mount | grep -E ' /data | /system '", "df -h /data", "ping -c 1 -W 3 8.8.8.8", "ls /system/bin/enable_nativebridge",
          "pm list packages | head -5", "cmd package help 2>&1 | grep -i install | head"]:
    print("###", c); print(run(c, 20)[-1500:])
print(f"summary accel={accel} prompt={prompt} booted={booted} total={time.time()-t0:.0f}s")
q.kill()
