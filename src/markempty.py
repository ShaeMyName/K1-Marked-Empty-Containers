#!/usr/bin/env python3
"""
Marked Empty Containers  (KOTOR 1 / swkotor.exe)

Appends " (empty)" to the floating hover/reticle name of any container or
lootable corpse that currently holds nothing -- so you can tell an empty
container from a full one at a glance, without opening it. Works the moment
you first see an initially-empty container, and updates live the instant you
loot one empty while still in the room.

How it works (for the curious):
  KOTOR's hover label is built by CSWGuiTargetActionMenu::UpdateNameLabel,
  which assembles the object's name into a TEMPORARY CExoString and hands it
  to SetNameLabel for display. This patch redirects that one call into a
  short routine in unused space at the end of .text. The routine checks
  whether the hovered object is a placeable that owns an item repository
  ([server+0x324] != 0) and currently has zero items (GetItemCount == 0);
  if so it appends " (empty)" to the TEMPORARY string only. The object's
  real name, the loot-window title, and scripting are never touched.
  Lootable corpses are "Remains" placeables, so they are covered too.

Scope: a 5-byte redirect at one call site, plus a ~140-byte routine written
into .text padding. No 2DA or other game files are edited, so it stacks
cleanly with other mods. Saves are unaffected.

Usage:  markempty apply   |   markempty revert
"""
import sys, os, struct, shutil

# ---- engine addresses (identical across the GOG/Steam/CD 1.03 builds) ----
VT_PLACEABLE   = 0x007537D0   # CSWCPlaceable_vtable (client)
GETSERVEROBJ   = 0x0063D4B0   # CSWCObject::GetServerObject(this)            -> server obj
GETITEMCOUNT   = 0x00587710   # CSWSPlaceable::GetItemCount(this, flag)      flag=0 -> count ALL
OPASSIGN_CSTR  = 0x005E5140   # CExoString::operator=(char const*)
SETNAMELABEL   = 0x00685AF0   # CSWGuiTargetActionMenu::SetNameLabel(CExoString*)

# Byte guards: verify these functions look as expected before touching anything.
GUARDS = {
    GETSERVEROBJ: bytes.fromhex('568bf1'),            # push esi; mov esi,ecx
    GETITEMCOUNT: bytes.fromhex('8b8124030000'),      # mov eax,[ecx+0x324]
    OPASSIGN_CSTR: bytes.fromhex('558b6c2408'),       # push ebp; mov ebp,[esp+8]
    SETNAMELABEL: bytes.fromhex('83ec50'),            # sub esp,0x50
}

# Locate the redirect site by pattern (NOT a hardcoded offset), so a wrong/
# unsupported exe simply doesn't match and nothing is changed:
#   lea ecx,[esp+0x20] ; push ecx ; mov ecx,edi ; call SetNameLabel
#   lea ecx,[esp+0x20] ; mov dword[edi+0x16dc],...   <- tail disambiguates from 24 lookalikes
HOOK_PAT = [0x8D,0x4C,0x24,0x20, 0x51, 0x8B,0xCF, 0xE8, None,None,None,None,
            0x8D,0x4C,0x24,0x20, 0xC7,0x87,0xDC,0x16,0x00,0x00]
HOOK_CALL_OFF = 7                                    # the 0xE8 is 7 bytes into the pattern

SUFFIX = " (empty)"                                  # the appended text (for reference)
# The routine writes these characters into a scratch buffer as INSTRUCTION IMMEDIATES
# (mov dword[edi], "...") and then writes its OWN NUL terminator. There is NO suffix
# data region stored in the exe, so another cave-using patch has nothing to clobber:
# the displayed string is always exactly "<name> (empty)\0". The routine also ends on
# its final jmp (a backward rel32 -> high byte 0xFF), so it has no trailing zero and a
# later largest-zero-run patch (e.g. Fair Pazaak) skips the whole block. This makes
# the two patches safe in EITHER order.
CODE_LEN = 132                                       # the whole routine; no data follows it
# First bytes of our routine — detects an already-patched exe (ANY version of this mod):
CAVE_SIG = [0x60,0x8B,0x55,0x08,0x85,0xD2, None,None, 0x8B,0x02, 0x3D,0xD0,0x37,0x75,0x00]
# Byte sequence unique to THIS version ('mov dword[edi], " (em"') — lets us tell a
# current install apart from an older one so we can prompt an upgrade instead of no-op.
CUR_MARK = b"\xC7\x07\x20\x28\x65\x6D"
CUR_MARK_OFF = 85
BAK_SUFFIX = ".MarkEmpty.bak"


def find_exe():
    here = os.path.dirname(os.path.abspath(sys.argv[0]))
    for c in (os.path.join(here, "swkotor.exe"),
              os.path.join(os.getcwd(), "swkotor.exe")):
        if os.path.isfile(c):
            return c
    return None


def parse_text(data):
    e = struct.unpack_from('<I', data, 0x3c)[0]; coff = e + 4
    nsec = struct.unpack_from('<H', data, coff+2)[0]
    optsize = struct.unpack_from('<H', data, coff+16)[0]; opt = coff + 20
    imgbase = struct.unpack_from('<I', data, opt+28)[0]
    sect = opt + optsize
    for i in range(nsec):
        o = sect + i*40
        if data[o:o+8].rstrip(b'\x00') == b'.text':
            vad = struct.unpack_from('<I', data, o+12)[0]
            rsz = struct.unpack_from('<I', data, o+16)[0]
            rpt = struct.unpack_from('<I', data, o+20)[0]
            return imgbase, vad, rpt, rsz
    raise RuntimeError(".text section not found")


def aob(data, pat):
    res = []; n = len(pat); first = pat[0]; i = 0
    while True:
        j = data.find(bytes([first]), i)
        if j < 0 or j + n > len(data): break
        if all(pat[k] is None or data[j+k] == pat[k] for k in range(1, n)):
            res.append(j)
        i = j + 1
    return res


def o2va(off, ib, vad, rpt): return ib + vad + (off - rpt)
def va2o(va, ib, vad, rpt): return rpt + (va - ib - vad)


def build_cave(cave_va, set_va):
    """Emit the routine bytes. Self-contained: the suffix text is written via
    instruction immediates (no suffix data to clobber) and the routine ends on its
    jmp, so only cave_va affects the final jmp displacement."""
    done = 126                                        # offset of 'popad' (DONE)
    def jz(at):  return bytes([0x74, (done-(at+2)) & 0xff])
    def jne(at): return bytes([0x75, (done-(at+2)) & 0xff])

    b = bytearray()
    b += bytes([0x60])                                # 0   pushad
    b += bytes.fromhex('8B5508')                      # 1   mov edx,[ebp+8]      ; target client obj
    b += bytes.fromhex('85D2')                        # 4   test edx,edx
    b += jz(6)                                        # 6   jz DONE
    b += bytes.fromhex('8B02')                        # 8   mov eax,[edx]        ; vtable
    b += bytes([0x3D]) + struct.pack('<I', VT_PLACEABLE)  # 10 cmp eax, CSWCPlaceable_vtable
    b += jne(15)                                      # 15  jne DONE
    b += bytes.fromhex('8BCA')                        # 17  mov ecx,edx
    b += bytes([0xB8]) + struct.pack('<I', GETSERVEROBJ)  # 19 mov eax, GetServerObject
    b += bytes.fromhex('FFD0')                        # 24  call eax            ; eax = server
    b += bytes.fromhex('85C0')                        # 26  test eax,eax
    b += jz(28)                                       # 28  jz DONE
    b += bytes.fromhex('8B8824030000')                # 30  mov ecx,[eax+0x324] ; item repository
    b += bytes.fromhex('85C9')                        # 36  test ecx,ecx
    b += jz(38)                                       # 38  jz DONE             ; no inventory -> skip
    b += bytes.fromhex('8BC8')                        # 40  mov ecx,eax         ; ecx = server
    b += bytes.fromhex('6A00')                        # 42  push 0              ; flag=0 (count ALL)
    b += bytes([0xB8]) + struct.pack('<I', GETITEMCOUNT)  # 44 mov eax, GetItemCount
    b += bytes.fromhex('FFD0')                        # 49  call eax            ; eax = count (ret 4)
    b += bytes.fromhex('85C0')                        # 51  test eax,eax
    b += bytes([0x75, (done-(53+2)) & 0xff])          # 53  jnz DONE            ; not empty -> skip
    b += bytes.fromhex('8B742424')                    # 55  mov esi,[esp+0x24]  ; pName (CExoString*)
    b += bytes.fromhex('8B36')                        # 59  mov esi,[esi]       ; name data (char*)
    b += bytes.fromhex('85F6')                        # 61  test esi,esi
    b += jz(63)                                       # 63  jz DONE             ; empty name -> skip
    b += bytes.fromhex('81EC00010000')                # 65  sub esp,0x100       ; scratch buffer
    b += bytes.fromhex('8BFC')                        # 71  mov edi,esp         ; edi = buf
    # CN: copy name (NUL not copied) -- off 73
    b += bytes.fromhex('8A06')                        # 73  mov al,[esi]
    b += bytes.fromhex('84C0')                        # 75  test al,al
    b += bytes.fromhex('7406')                        # 77  jz WS  (+6 -> 85)
    b += bytes.fromhex('8807')                        # 79  mov [edi],al
    b += bytes.fromhex('46')                          # 81  inc esi
    b += bytes.fromhex('47')                          # 82  inc edi
    b += bytes.fromhex('EBF4')                        # 83  jmp CN (-12 -> 73)
    # WS: write " (empty)\0" straight from immediates (no data region) -- off 85
    b += bytes.fromhex('C707') + b' (em'              # 85  mov dword[edi],   " (em"  (0x6D652820)
    b += bytes.fromhex('C74704') + b'pty)'            # 91  mov dword[edi+4], "pty)"  (0x29797470)
    b += bytes.fromhex('C6470800')                    # 98  mov byte[edi+8], 0        ; NUL terminator
    b += bytes.fromhex('8B8C2424010000')              # 102 mov ecx,[esp+0x124] ; pName
    b += bytes.fromhex('8D1424')                      # 109 lea edx,[esp]       ; buf
    b += bytes.fromhex('52')                          # 112 push edx
    b += bytes([0xB8]) + struct.pack('<I', OPASSIGN_CSTR)  # 113 mov eax, operator=
    b += bytes.fromhex('FFD0')                        # 118 call eax            ; ret 4
    b += bytes.fromhex('81C400010000')                # 120 add esp,0x100
    # DONE: -- off 126
    b += bytes.fromhex('61')                          # 126 popad
    b += bytes([0xE9]) + struct.pack('<i', set_va - (cave_va + 127 + 5))  # 127 jmp SetNameLabel
    assert len(b) == CODE_LEN, "cave code len %d != %d" % (len(b), CODE_LEN)
    return bytes(b)


def largest_zero_run(data, rpt, rsz, need):
    best = (0, 0); cur = 0
    for k in range(rpt, rpt+rsz):
        if data[k] == 0:
            cur += 1
            if cur > best[0]: best = (cur, k-cur+1)
        else:
            cur = 0
    return best[1] if best[0] >= need else None


def apply(path):
    data = bytearray(open(path, 'rb').read())
    ib, vad, rpt, rsz = parse_text(data)
    cm = aob(data, CAVE_SIG)
    if cm:
        off = cm[0]
        if data[off+CUR_MARK_OFF:off+CUR_MARK_OFF+len(CUR_MARK)] == CUR_MARK:
            print("Already patched (current version) -- nothing to do."); return 0
        print("An OLDER version of this patch is installed.")
        print("Run the Revert step first, then Apply again to upgrade.")
        return 1
    # locate the redirect site
    hm = aob(data, HOOK_PAT)
    if len(hm) == 0:
        print("ERROR: hover-name code not found. This swkotor.exe version isn't supported."); return 1
    if len(hm) > 1:
        print("ERROR: pattern matched %d places; aborting to be safe." % len(hm)); return 1
    call_off = hm[0] + HOOK_CALL_OFF
    call_va = o2va(call_off, ib, vad, rpt)
    ret_va = call_va + 5
    rel = struct.unpack_from('<i', data, call_off+1)[0]
    set_va = ret_va + rel                              # derived SetNameLabel address
    if set_va != SETNAMELABEL:
        print("ERROR: redirect target 0x%08X unexpected; aborting." % set_va); return 1
    # sanity-guard the engine functions we call
    for va, sig in GUARDS.items():
        off = va2o(va, ib, vad, rpt)
        if data[off:off+len(sig)] != sig:
            print("ERROR: function at 0x%08X doesn't match; aborting." % va); return 1
    # place the routine in the largest .text zero-run (coexists w/ other cave mods)
    cave_off = largest_zero_run(data, rpt, rsz, CODE_LEN)
    if cave_off is None:
        print("ERROR: no code cave available; aborting."); return 1
    cave_va = o2va(cave_off, ib, vad, rpt)
    cave = build_cave(cave_va, set_va)
    bak = path + BAK_SUFFIX
    if not os.path.exists(bak): shutil.copy2(path, bak)
    data[cave_off:cave_off+len(cave)] = cave
    data[call_off:call_off+5] = bytes([0xE8]) + struct.pack('<i', cave_va - ret_va)
    open(path, 'wb').write(data)
    print("SUCCESS: Marked Empty Containers applied.")
    print("  redirect site : 0x%08X" % call_va)
    print("  routine        : 0x%08X (%d bytes)" % (cave_va, len(cave)))
    print("  backup         : %s" % os.path.basename(bak))
    return 0


def revert(path):
    bak = path + BAK_SUFFIX
    if os.path.exists(bak):
        shutil.copy2(bak, path)
        print("SUCCESS: reverted swkotor.exe from backup."); return 0
    # no backup -> signature un-patch
    data = bytearray(open(path, 'rb').read())
    ib, vad, rpt, rsz = parse_text(data)
    cm = aob(data, CAVE_SIG)
    if not cm:
        print("Not patched (and backup missing). Nothing done."); return 1
    cave_off = cm[0]
    cave_va = o2va(cave_off, ib, vad, rpt)
    # SetNameLabel addr is encoded in the routine's final 'popad; jmp rel32' (61 E9)
    j = data.find(b'\x61\xE9', cave_off, cave_off + 256)
    if j < 0:
        print("ERROR: couldn't locate the routine's jmp; aborting."); return 1
    rel = struct.unpack_from('<i', data, j+2)[0]
    set_va = o2va(j+1, ib, vad, rpt) + 5 + rel
    # find our redirect: a 'call cave' whose target is cave_va
    site = None
    for h in aob(data, [0xE8, None, None, None, None]):
        tgt = o2va(h, ib, vad, rpt) + 5 + struct.unpack_from('<i', data, h+1)[0]
        if tgt == cave_va:
            # confirm it sits right after 'lea ecx,[esp+0x20]; push ecx; mov ecx,edi'
            if list(data[h-7:h]) == [0x8D,0x4C,0x24,0x20,0x51,0x8B,0xCF]:
                site = h; break
    if site is None:
        print("ERROR: couldn't locate the redirect to restore; aborting."); return 1
    ret_va = o2va(site, ib, vad, rpt) + 5
    data[site:site+5] = bytes([0xE8]) + struct.pack('<i', set_va - ret_va)  # restore call SetNameLabel
    data[cave_off:cave_off + CODE_LEN] = b'\x00' * CODE_LEN
    open(path, 'wb').write(data)
    print("SUCCESS: reverted via signature (no backup was present)."); return 0


def main():
    cmd = (sys.argv[1].lower() if len(sys.argv) > 1 else "")
    if cmd not in ("apply", "revert"):
        print("Marked Empty Containers (KOTOR 1)")
        print("Usage: markempty apply | markempty revert"); return 2
    path = find_exe()
    if not path:
        print("ERROR: swkotor.exe not found.")
        print("Put this program (and the .bat files) in your KOTOR folder,")
        print("next to swkotor.exe, then run it again.")
        return 1
    print("Target: %s\n" % path)
    return apply(path) if cmd == "apply" else revert(path)


if __name__ == "__main__":
    sys.exit(main())
