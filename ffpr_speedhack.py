#!/usr/bin/env python3
from capstone import *
from capstone.x86 import *
import pefile
import sys

AUTOBATTLE_FLAG_MARKER = b"\x0f\xb6\x40\x19\xc3"

SPEED_TO_HEX = {"1.5x": b"\x00\x00\xc0\x3f",
                "2x": b"\x00\x00\x00\40",
                "2.5x": b"\x00\x00\x20\x40",
                "3x": b"\x00\x00\x40\x40",
                "4x": b"\x00\x00\x80\x40",
                "5x": b"\x00\x00\xa0\x40"}
# 1: e8 da ce f7 ff 84 c0 0f 84 c5 00 00 00 f3 0f 59 35 92 87 35 00 e9 b8 00 00 00 33 c9 e8 3e c6 e1 ff 0f 57 f6
# 2: e8 ba 23 f9 ff 84 c0 0f 84 c5 00 00 00 f3 0f 59 35 62 50 51 01 e9 b8 00 00 00 33 c9 e8 8e 4a fc 00 0f 57 f6
# 5: e8 3a 58 07 00 84 c0 0f 84 c5 00 00 00 f3 0f 59 35 fa d0 64 01 e9 b8 00 00 00 33 c9 e8 0e 3c 0b 01 0f 57 f6
# 6: e8 ec 30 15 00 84 c0 0f 84 c4 00 00 00 f3 0f 59 35 04 40 d4 00 e9 b7 00 00 00 33 c9 e8 f0 d3 c4 ff 0f 57 f6
always_fast = False
autobattle_speed = "1.5x"

md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True
md.skipdata = True

print("Parsing GameAssembly.dll...")
try:
    pe = pefile.PE("GameAssembly.dll", fast_load=True)
except:
    print("Script must be run from the same directory as a Final Fantasy Pixel Remaster GameAssembly.dll.")
    sys.exit(1)

for section in pe.sections:
    if section.Name == b'il2cpp\x00\x00':
        offset = section.VirtualAddress
        code = section.get_data()
        code_size = len(code)
        print("Section offset %x code_size %x" % (offset, code_size))
        break
# Find our marker for the autobattle flag function
autobattle_flag_pos = code.index(AUTOBATTLE_FLAG_MARKER)
# Find where the function starts
autobattle_fn_start = autobattle_flag_pos - 100 + (code[autobattle_flag_pos-100:autobattle_flag_pos].rfind(b'\xcc')  +1)
print("Found autobattle flag function at il2cpp section offset 0x%x\n" % autobattle_fn_start)

found = False
pos = 0

print("Locating victim code...")
while True:
    loc = code[pos:].find(b'\x00\x00\x00\xf3\x0f\x59\x35')
    pos += loc + 1
    if loc == -1:
        print("Failed to find victim code, are you using a stock DLL?")
        sys.exit(1)

    start = pos - 11

    if code[start] != 0xe8:
        continue
    if code[start:].find(b'\x84\xc0\x0f\x84') != 5:
        continue
    if code[start + 21] != 0xe9:
        continue
    if code[start:].find(b'\x00\x00\x00\x33\xc9\xe8') != 23:
        continue
    if code[start:].find(b'\x0f\x57\xf6') != 33:
        continue

    pos = start
    break

print("Victim found at 0x%x" % pos)
je = None
test = None
call = None
mulss = None
# Leftover from when I used to disassemble lots of code, could just be replaced
# with disassembling instruction by instruction
for i in md.disasm(code[pos:pos+100], offset+pos):
    if je is not None:
        if i.mnemonic == "mulss":
            mulss = i
            break
        else:
            test = None
            call = None
            je = None
    if test is not None:
        if i.mnemonic == "je":
            je = i
        else:
            test = None
            call = None
    if call is not None:
        if i.mnemonic == "test" and i.op_str == "al, al":
            test = i
        elif i.mnemonic == "cmp" and i.op_str == "al, 0xff":
            test = i
            always_fast = True
        else:
            call = None
        continue
    if i.mnemonic == "call":
        if i.op_str == hex(offset+autobattle_fn_start):
            call = i
            print(call, hex(i.address))

if mulss is None:
    print("Somehow messed up disassembling the victim code!")
    sys.exit(1)

for i in mulss.operands:
    if i.type == X86_OP_MEM:
        speed_ptr = i.mem.disp

print("\nFinding the .rdata section for the game speed...")
for section in pe.sections:
    if section.Name == b'.rdata\x00\x00':
        rdata = section.get_data()
        rdata_offset = section.VirtualAddress
        break

speed_offset = mulss.address + speed_ptr
print(hex(speed_offset), hex(rdata_offset))
search = rdata[speed_offset - rdata_offset:speed_offset + 16 - rdata_offset]
pos = search.find(b"\x00\x00\xc0\x3f")
print(search.hex())
if pos == -1:
    # you only live once
    pos = 8
speed_pos = speed_offset + pos
speed = search[pos:pos+4]

if speed not in SPEED_TO_HEX.values():
    print("Couldn't find autobattle speed.")
    print("Try using a vanilla GameAssembly.dll!")
    sys.exit(1)
else:
    # yeah I know this is backwards
    for (key, value) in SPEED_TO_HEX.items():
        if speed == value:
            autobattle_speed = key
            break

print("------------------------------------------------")
print("")
print("Parsing and decompilation successful.")
if always_fast:
    print("Your game always has autobattle speed on during battles.")
else:
    print("Your game only has autobattle speed on during autobattle.")

print()
autobattle_response = None
while autobattle_response not in ["y", "n"]:
    autobattle_response = input("Do you want your battles to always have autobattle speed? [y/n]: ")

print("\nYour game currently has autobattle speed %s." % autobattle_speed)
print()
speed_response = None
while speed_response not in SPEED_TO_HEX.keys():
    speed_response = input("Choose a speed from %s: " % str(list(SPEED_TO_HEX.keys())))

print()

if speed_response != autobattle_speed:
    print("Found speed at 0x%x, patching..." % speed_pos)
    pe.set_bytes_at_rva(speed_pos, SPEED_TO_HEX[speed_response])

print()
if autobattle_response == "y" and always_fast == False:
    print("Replacing test al,al with cmp al,0xff...")
    pe.set_bytes_at_rva(test.address, b"\x3c\xff")
    always_fast = True
elif autobattle_response == "n" and always_fast == True:
    print("Replacing cmp al,0xff with test al,al...")
    pe.set_bytes_at_rva(test.address, b"\x84\xc0")
    always_fast = False

if always_fast:
    zoomy = "-ZOOMY"
else:
    zoomy = ""

filename = format("GameAssembly-%s%s.dll" % (speed_response, zoomy))
pe.write(filename)

print("\nChanges saved to %s.  Make sure to back up the original!" % filename)
