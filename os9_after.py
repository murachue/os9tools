# MIT License
#
# Copyright (c) 2021 Murachue
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# OS-9/68000 easy-to-read filter for IDA 6.9 (old!)
# run this after loading OS-9/68000 Executable or makecode.

def Codes():
    # TODO: code at 0 is ignored...
    ea = 0
    while True:
        ea = idaapi.find_code(ea, idaapi.SEARCH_DOWN)
        if ea == idaapi.BADADDR:
            return
        yield ea

# idautils
def decode(ea):
    il = idaapi.decode_insn(ea)
    if il == 0:
        raise Exception("?code but cannot decode %s" % ea)
    return idaapi.cmd.copy()

datasegea = idaapi.get_segm_by_name(".data").startEA
for ea in Codes():
    insn = decode(ea)
    # reference data (a6)
    for i in [0, 1]:
        op = insn[i]
        if op.type == idaapi.o_displ and op.reg == 14: #a6
            idaapi.op_offset(ea, i, idaapi.REF_OFF32 | idaapi.REFINFO_NOBASE, idaapi.BADADDR, datasegea + 0x8000, 0)
    # reference pcrel
    if insn.get_canon_mnem() in ["move", "movea"]:
        next = decode(ea + insn.size)
        # it seems X in "jsr (pc,X.l)" in specflag1.
        if next.get_canon_mnem() == "jsr" and next[0].specflag1 == insn[1].reg:
            # tweak movea base
            idaapi.op_offset(ea, 0, idaapi.REF_OFF32 | idaapi.REFINFO_NOBASE, idaapi.BADADDR, ea + 8, 0)
            targea = insn[0].value + ea + 8
            #idaapi.create_insn(targea)
            idaapi.auto_mark_range(targea, targea + 1, idaapi.AU_PROC)
    # os9 (trap 0)
    if insn.get_canon_mnem() == "trap":
        idaapi.do_unknown(ea + 2, idaapi.DOUNK_SIMPLE | idaapi.DOUNK_NOTRUNC)
        idaapi.doWord(ea + 2, 2)
        idaapi.create_insn(ea + 4)
