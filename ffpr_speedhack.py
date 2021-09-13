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
        break
# Find our marker for the autobattle flag function
autobattle_flag_pos = code.index(AUTOBATTLE_FLAG_MARKER)
# Find where the function starts
autobattle_fn_start = autobattle_flag_pos - 100 + (code[autobattle_flag_pos-100:autobattle_flag_pos].rfind(b'\xcc')  +1)
print("Found autobattle flag function at il2cpp section offset 0x%x\n" % autobattle_fn_start)

print("Disassembling (may be slow)...\n")
call = None
test = None
je = None
mulss = None

# Disassembling the entire section is a gigantic memory hog
steps = 0x10000
index = 0
while steps*index < code_size:
    for i in md.disasm(code[index*steps:(index+1)*steps], offset+(index*steps)):
        if je is not None:
            if i.mnemonic == "mulss":
                mulss = i
                break
        if test is not None:
            if i.mnemonic == "je":
                je = i
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
    if mulss is not None:
        break
    index += 1

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
