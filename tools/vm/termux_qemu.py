"""Fetches QEMU (x86_64 system emulator, headless) for Android arm64 from the Termux package
repository, with every library it needs, and lays it out for the APK:
  out/libqemu.so            the emulator
  out/lib<name>.so          its libraries, renamed to unversioned lib*.so names
  share/                    BIOS / option ROM files (go to assets)
Library names inside the binaries are rewritten with patchelf so Android's linker finds them
in the app's native library folder.  Usage: termux_qemu.py <outdir> <sharedir>"""
import gzip, io, os, re, subprocess, sys, tarfile, urllib.request, lzma, shutil, hashlib

REPO = "https://packages-cf.termux.dev/apt/termux-main/"
ARCH = "aarch64"
ROOT_PKG = sys.argv[3] if len(sys.argv) > 3 else "qemu-system-x86-64-headless"
out, share = sys.argv[1], sys.argv[2]
os.makedirs(out, exist_ok=True); os.makedirs(share, exist_ok=True)

def get(url):
    with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "corekit-ci"}), timeout=120) as r:
        return r.read()

idx = get(REPO + f"dists/stable/main/binary-{ARCH}/Packages")
pk = {}
for block in idx.decode("utf-8", "replace").split("\n\n"):
    f = {}
    for line in block.splitlines():
        if ":" in line and not line.startswith(" "):
            k, v = line.split(":", 1); f[k.strip()] = v.strip()
    if "Package" in f:
        pk[f["Package"]] = f

def deps(name):
    d = pk[name].get("Depends", "")
    res = []
    for part in d.split(","):
        part = part.strip()
        if not part: continue
        alt = part.split("|")[0].strip()
        res.append(re.sub(r"\s*\(.*\)", "", alt))
    return res

want, stack = [], [ROOT_PKG]
while stack:
    n = stack.pop()
    if n in want: continue
    if n not in pk:
        print("missing package", n); continue
    want.append(n); stack.extend(deps(n))
print("packages:", " ".join(sorted(want)))

work = "/tmp/termux-x"; shutil.rmtree(work, ignore_errors=True); os.makedirs(work)
PREFIX = "data/data/com.termux/files/usr/"
for n in want:
    deb = get(REPO + pk[n]["Filename"])
    if hashlib.sha256(deb).hexdigest() != pk[n].get("SHA256", ""):
        sys.exit("checksum mismatch " + n)
    # .deb = ar archive with data.tar.xz
    pos = 8
    while pos < len(deb):
        name = deb[pos:pos+16].decode().strip(); size = int(deb[pos+48:pos+58].decode().strip())
        body = deb[pos+60:pos+60+size]; pos += 60 + size + (size & 1)
        if name.startswith("data.tar"):
            if name.endswith(".xz"): body = lzma.decompress(body)
            elif name.endswith(".gz"): body = gzip.decompress(body)
            tarfile.open(fileobj=io.BytesIO(body)).extractall(work)

usr = os.path.join(work, PREFIX)
libdir = os.path.join(usr, "lib")
binp = os.path.join(usr, "bin", "qemu-system-x86_64")
assert os.path.exists(binp), "qemu binary missing"

def needed(path):
    o = subprocess.run(["readelf", "-d", path], capture_output=True, text=True).stdout
    return re.findall(r"\(NEEDED\)\s+Shared library: \[(.+?)\]", o)

SYSTEM = {"libc.so", "libm.so", "libdl.so", "liblog.so", "libz.so", "libandroid.so", "libEGL.so", "libGLESv2.so", "libvulkan.so", "libmediandk.so", "libOpenSLES.so", "libjnigraphics.so", "libnativewindow.so", "libc++_shared.so_"}
def resolve(lib):
    p = os.path.join(libdir, lib)
    return os.path.realpath(p) if os.path.exists(p) else None

def flat(lib):  # libglib-2.0.so.0 -> libglib-2.0.so ; must start with lib and end with .so
    b = re.sub(r"(\.so)(\.\d+)*$", r"\1", lib)
    if not b.startswith("lib"): b = "lib" + b
    return b

copied, queue = {}, [("libqemu.so", binp)]
while queue:
    dst, src = queue.pop()
    if dst in copied: continue
    target = os.path.join(out, dst); shutil.copy(src, target); os.chmod(target, 0o755)
    copied[dst] = src
    for lib in needed(src):
        if lib in SYSTEM: continue
        r = resolve(lib)
        if not r:
            print("WARN not in termux libs:", lib, "(needed by", dst + ")"); continue
        f = flat(lib)
        if f != lib:
            subprocess.run(["patchelf", "--replace-needed", lib, f, target], check=True)
        queue.append((f, r))
for dst in copied:
    t = os.path.join(out, dst)
    subprocess.run(["patchelf", "--remove-rpath", t], check=True)
    if dst != "libqemu.so":
        subprocess.run(["patchelf", "--set-soname", dst, t], check=True)

qs = os.path.join(usr, "share", "qemu")
for f in ["bios-256k.bin", "kvmvapic.bin", "linuxboot_dma.bin", "linuxboot.bin", "efi-e1000.rom", "efi-virtio.rom", "vgabios-stdvga.bin", "vgabios.bin", "multiboot_dma.bin", "pxe-e1000.rom"]:
    if os.path.exists(os.path.join(qs, f)): shutil.copy(os.path.join(qs, f), share)
if os.path.isdir(os.path.join(qs, "keymaps")): shutil.copytree(os.path.join(qs, "keymaps"), os.path.join(share, "keymaps"), dirs_exist_ok=True)
tot = 0
for f in sorted(os.listdir(out)):
    s = os.path.getsize(os.path.join(out, f)); tot += s
    print(f"{s/1e6:7.2f} MB  {f}  needs: {', '.join(needed(os.path.join(out, f)))}")
print(f"total {tot/1e6:.1f} MB; share: {sorted(os.listdir(share))}")
print("qemu version:", pk.get(ROOT_PKG, {}).get("Version"))
