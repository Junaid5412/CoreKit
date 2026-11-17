"""Builds rsrc_windows_amd64.syso: app icon, admin manifest and version info (COFF .rsrc object for the Go linker)."""
import struct, io, os
HERE = os.path.dirname(os.path.abspath(__file__))
os.chdir(HERE)
VER = open(os.path.join(HERE, "..", "..", "VERSION")).read().strip()
V4 = tuple(int(x) for x in (VER.split("-")[0].split(".") + ["0", "0", "0"])[:4])
from PIL import Image, ImageDraw, ImageFilter

# ---------- icon ----------
def draw_icon(S=1024):
    im = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    # rounded square with vertical gradient
    bg = Image.new('RGBA', (S, S))
    d = ImageDraw.Draw(bg)
    for y in range(S):
        t = y / S
        d.line([(0, y), (S, y)], fill=(int(16 - 6*t), int(34 - 14*t), int(38 - 14*t), 255))
    mask = Image.new('L', (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S-1, S-1], radius=int(S*.23), fill=255)
    im.paste(bg, (0, 0), mask)
    # glow layer
    glow = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    g = ImageDraw.Draw(glow)
    teal = (45, 212, 191, 255)
    import math
    c, w = S/2, int(S*.07)
    hexp = lambda r: [(c + r*math.cos(math.radians(a)), c + r*math.sin(math.radians(a))) for a in range(-90, 270, 60)]
    g.line(hexp(S*.31) + [hexp(S*.31)[0]], fill=teal, width=w, joint='curve')
    g.polygon(hexp(S*.125), fill=teal)
    blur = glow.filter(ImageFilter.GaussianBlur(S*.035))
    im = Image.alpha_composite(im, Image.composite(blur, Image.new('RGBA', (S, S), (0,0,0,0)), mask))
    d = ImageDraw.Draw(im)
    d.line(hexp(S*.31) + [hexp(S*.31)[0], hexp(S*.31)[1]], fill=teal, width=w, joint='curve')
    d.polygon(hexp(S*.125), fill=teal)
    # outer subtle ring
    ring = Image.new('RGBA', (S, S), (0,0,0,0))
    ImageDraw.Draw(ring).rounded_rectangle([2, 2, S-3, S-3], radius=int(S*.23), outline=(45, 212, 191, 70), width=int(S*.012))
    im = Image.alpha_composite(im, ring)
    return im

big = draw_icon()
sizes = [16, 24, 32, 48, 64, 128, 256]
pngs = []
for s in sizes:
    b = io.BytesIO(); big.resize((s, s), Image.LANCZOS).save(b, 'PNG'); pngs.append(b.getvalue())
big.resize((256, 256), Image.LANCZOS).save('icon-preview.png')
ico = io.BytesIO()
ico.write(struct.pack('<HHH', 0, 1, len(sizes)))
off = 6 + 16*len(sizes)
for s, p in zip(sizes, pngs):
    ico.write(struct.pack('<BBBBHHII', s % 256, s % 256, 0, 0, 1, 32, len(p), off)); off += len(p)
for p in pngs: ico.write(p)
open('CoreKit.ico', 'wb').write(ico.getvalue())

group = struct.pack('<HHH', 0, 1, len(sizes))
for i, (s, p) in enumerate(zip(sizes, pngs)):
    group += struct.pack('<BBBBHHIH', s % 256, s % 256, 0, 0, 1, 32, len(p), i + 1)

# ---------- manifest ----------
manifest = b'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="CoreKit" version="%d.%d.%d.%d" processorArchitecture="amd64"/>
  <description>CoreKit</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
</assembly>
''' % V4

# ---------- version info ----------
def pad4(b): return b + b'\0' * ((4 - len(b) % 4) % 4)
def node(key, value=b'', wtype=0, children=(), vlen=None):
    k = (key + '\0').encode('utf-16-le')
    hdr_len = 6 + len(k)
    body = pad4(struct.pack('<HHH', 0, 0, 0) + k)
    if value: body = pad4(body + value)
    for ch in children: body = pad4(body) + ch
    if vlen is None: vlen = len(value) // 2 if wtype == 1 else len(value)
    return struct.pack('<HHH', len(body), vlen, wtype) + body[6:]
def sval(k, v):
    vb = (v + '\0').encode('utf-16-le')
    return node(k, vb, 1)
ver = V4
fixed = struct.pack('<13I', 0xFEEF04BD, 0x00010000, (ver[0] << 16) | ver[1], (ver[2] << 16) | ver[3],
                    (ver[0] << 16) | ver[1], (ver[2] << 16) | ver[3], 0x3F, 0, 0x40004, 1, 0, 0, 0)
strings = [('CompanyName', 'CoreKit'), ('FileDescription', 'CoreKit System Toolkit'),
           ('FileVersion', '%d.%d.%d.%d' % V4), ('InternalName', 'CoreKit'),
           ('LegalCopyright', 'Free to use'), ('OriginalFilename', 'CoreKit.exe'),
           ('ProductName', 'CoreKit'), ('ProductVersion', VER)]
stable = node('040904B0', b'', 1, [sval(k, v) for k, v in strings])
sfi = node('StringFileInfo', b'', 1, [stable])
vfi = node('VarFileInfo', b'', 1, [node('Translation', struct.pack('<HH', 0x0409, 0x04B0), 0)])
version = node('VS_VERSION_INFO', fixed, 0, [sfi, vfi])

# ---------- resource tree -> COFF ----------
LANG = 0x0409
res = {3: {i + 1: p for i, p in enumerate(pngs)}, 14: {1: group}, 16: {1: version}, 24: {1: manifest}}
types = sorted(res)
def dir_size(n): return 16 + 8*n
off = dir_size(len(types))
type_dir_off, name_dir_off = {}, {}
for t in types:
    type_dir_off[t] = off; off += dir_size(len(res[t]))
lang_dir_off = {}
for t in types:
    for i in sorted(res[t]): lang_dir_off[(t, i)] = off; off += dir_size(1)
data_entry_off = {}
for t in types:
    for i in sorted(res[t]): data_entry_off[(t, i)] = off; off += 16
data_off = {}
for t in types:
    for i in sorted(res[t]):
        off = (off + 7) & ~7; data_off[(t, i)] = off; off += len(res[t][i])
total = (off + 7) & ~7
buf = bytearray(total)
def put_dir(at, entries):
    struct.pack_into('<IIHHHH', buf, at, 0, 0, 4, 0, 0, len(entries))
    for k, (ident, target, is_dir) in enumerate(entries):
        struct.pack_into('<II', buf, at + 16 + 8*k, ident, target | (0x80000000 if is_dir else 0))
put_dir(0, [(t, type_dir_off[t], True) for t in types])
relocs = []
for t in types:
    put_dir(type_dir_off[t], [(i, lang_dir_off[(t, i)], True) for i in sorted(res[t])])
    for i in sorted(res[t]):
        put_dir(lang_dir_off[(t, i)], [(LANG, data_entry_off[(t, i)], False)])
        de = data_entry_off[(t, i)]
        struct.pack_into('<IIII', buf, de, data_off[(t, i)], len(res[t][i]), 0, 0)
        relocs.append(de)
        buf[data_off[(t, i)]:data_off[(t, i)] + len(res[t][i])] = res[t][i]

raw_ptr = 20 + 40
reloc_ptr = raw_ptr + len(buf)
sym_ptr = reloc_ptr + 10*len(relocs)
coff = struct.pack('<HHIIIHH', 0x8664, 1, 0, sym_ptr, 1, 0, 0)
coff += struct.pack('<8sIIIIIIHHI', b'.rsrc', 0, 0, len(buf), raw_ptr, reloc_ptr, 0, len(relocs), 0, 0x40000040)
coff += bytes(buf)
for r in relocs: coff += struct.pack('<IIH', r, 0, 3)   # IMAGE_REL_AMD64_ADDR32NB vs .rsrc symbol
coff += struct.pack('<8sIhHBB', b'.rsrc', 0, 1, 0, 3, 0)
coff += struct.pack('<I', 4)
open('../rsrc_windows_amd64.syso', 'wb').write(coff)
print('syso', len(coff), 'bytes;', len(relocs), 'resources')
