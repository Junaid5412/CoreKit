"""Makes CoreKit's empty data-disk template: an 8 GB ext4 file system stored as only its
non-zero blocks (format read by vmWriteDisk in desktop/vm.go).
Usage: mktemplate.py <out.ckt> [size_gb]"""
import gzip, os, struct, subprocess, sys, tempfile
out = sys.argv[1]; gb = int(sys.argv[2]) if len(sys.argv) > 2 else 8
size = gb << 30
with tempfile.TemporaryDirectory() as d:
    img = os.path.join(d, "data.img")
    with open(img, "wb") as f: f.truncate(size)
    # features an Android 7-9 kernel (4.x) can mount
    subprocess.run(["mkfs.ext4", "-F", "-q", "-L", "data", "-m", "0", "-O", "^orphan_file,^metadata_csum_seed,^metadata_csum",
                    "-E", "lazy_itable_init=1,lazy_journal_init=1,discard", img], check=True)
    BS = 64 << 10
    zero = bytes(BS)
    with open(img, "rb") as f, gzip.open(out, "wb", 9) as g:
        g.write(b"CKT1" + struct.pack("<Q", size))
        off, run_off, run = 0, None, bytearray()
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
print(out, os.path.getsize(out), "bytes")
