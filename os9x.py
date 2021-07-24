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

# OS-9/68000 Executable File Loader for IDA 6.9 (old!)

import struct
import idaapi

FORMAT_EXE = 'OS-9/68000 Executable'

# TODO: what li.read returns/throws on short-read or EOF? (assuming partial str on short-read, None on EOF)
def read(li, bytes):
	d = li.read(bytes)
	if d is None or len(d) < bytes:
		raise EOFError
	return d
# big endian
def readb(li):
	return struct.unpack('>B', read(li, 1))[0]
def readw(li):
	return struct.unpack('>H', read(li, 2))[0]
def readl(li):
	return struct.unpack('>I', read(li, 4))[0]

def readasciz(li):
	chars = []
	while True:
		c = readb(li)
		if c == 0:
			return struct.pack(str(len(chars)) + "B", *chars)
		chars.append(c)

def addseg(startea, endea, base, use32, align, comb, name, sclass):
	s = idaapi.segment_t()
	s.startEA = startea
	s.endEA   = endea
	s.sel     = idaapi.setup_selector(base)
	s.bitness = use32
	s.align   = align
	s.comb    = comb
	return idaapi.add_segm_ex(s, name, sclass, idaapi.ADDSEG_NOSREG)

def loadbytes(ea, size, li):
	fileoffset = li.tell()
	_patchable = 1
	li.file2base(fileoffset, ea, ea + size, _patchable)
	li.seek(fileoffset + size) # I dunno file position is modified by file2base or not... ensure it is.

def loadseg(name, ea, size, segtype, li=None):
	base = ea >> 4 # make segment-related offset zero based
	_use32 = 1
	_align = idaapi.saRelByte # unkown...
	_comb = idaapi.scPub
	addseg(ea, ea + size, base, _use32, _align, _comb, name, segtype)
	if li:
		loadbytes(ea, size, li)

	# rollup to next "paragraph"(x86) that make next ea aligned to "paragraph" to be able to make next segment zero-offsetted
	return (ea + size + 15) & -16

# LoaderInput sourced Object
class LiObject(object):
	def __init__(self, li):
		for (k, f) in self._fields:
			setattr(self, k, f(li))

class Header(LiObject):
	# without magic (already read for check)
	_fields = [
		# ("magic", readw),
		("sysrev", readw),
		("size", readl),
		("owner", readl),
		("name", readl),
		("accs", readw),
		("type", readb),
		("lang", readb),
		("attr", readb),
		("revs", readb),
		("edit", readw),
		("usage", readl),
		("symbol", readl),
		("reserved", lambda li: read(li, 14)),
		("parity", readw),
	]

def accept_file(li, n):
	# only one format accepted
	if n != 0:
		return 0

	li.seek(0)

	if readw(li) != 0x4AFC:
		return 0

	li.seek(0)

	parity = reduce(lambda a, b: a ^ b, struct.unpack(">24H", li.read(48)), 0xFFFF)
	if parity != 0:
		return 0

	# TODO: check CRC24?

	return FORMAT_EXE

def load_file(li, neflags, format):
	# hey wrong man
	if format not in [FORMAT_EXE]:
		return 0

	# requires 68000 processor module. (should be 68070 for CD-i)
	idaapi.set_processor_type('68000', SETPROC_ALL | SETPROC_FATAL)

	# rewind
	li.seek(0)

	if readw(li) != 0x4AFC:
		raise RuntimeError('Wrong magic??')
	header = Header(li)
	hexec = None
	hexcpt = None
	hmem = None
	hstack = None
	hidata = None
	hirefs = None
	hinit = None
	hterm = None
	if header.type in [1, 11, 12, 13, 14]: # Prgm, TrapLib, Systm, Flmgr, Drivr
		hexec = readl(li)
		hexcpt = readl(li)
	if header.type in [1, 11, 14]: # Prgm, TrapLib, Drivr
		hmem = readl(li)
	if header.type in [1, 11]: # Prgm, TrapLib
		hstack = readl(li)
		hidata = readl(li)
		hirefs = readl(li)
	if header.type in [11]: # TrapLib
		hinit = readl(li)
		hterm = readl(li)

	# simply map whole to text (using header)
	li.seek(0)
	ea = 0
	textsegea = ea
	ea = loadseg(".text", ea, header.size, "CODE", li)

	def symbolize(symea, fields):
		for (name, width) in fields:
			if width == 1:
				idaapi.doByte(symea, 1)
			elif width == 2:
				idaapi.doWord(symea, 2)
			elif width == 4:
				idaapi.doDwrd(symea, 4)
			else:
				idaapi.doByte(symea, width)

			if Name is not None:
				idaapi.set_name(symea, name, idaapi.SN_CHECK)

			symea += width
	# symbolize header
	# common
	fields = [
		("M$ID", 2),
		("M$SysRev", 2),
		("M$Size", 4),
		("M$Owner", 4),
		("M$Name", 4),
		("M$Accs", 2),
		("M$Type", 1),
		("M$Lang", 1),
		("M$Attr", 1),
		("M$Revs", 1),
		("M$Edit", 2),
		("M$Usage", 4),
		("M$Symbol", 4),
		(None, 14),
		("M$Parity", 2),
	]

	# programmy 0x30-
	if header.type in [1, 11, 12, 13, 14]: # Prgm, TrapLib, Systm, Flmgr, Drivr
		fields += [
			("M$Exec", 4), # Flmgr/Drivr points to entry table.
			("M$Excpt", 4),
		]
	if header.type in [1, 11, 14]: # Prgm, TrapLib, Drivr
		fields += [
			("M$Mem", 4),
		]
	if header.type in [1, 11]: # Prgm, TrapLib
		fields += [
			("M$Stack", 4),
			("M$IData", 4),
			("M$IRefs", 4),
		]
	if header.type in [11]: # TrapLib
		fields += [
			("M$Init", 4),
			("M$Term", 4),
		]

	# device-descriptor 0x30-
	if header.type == 15: # Devic
		fields += [
			("M$Port", 4),
			("M$Vector", 1),
			("M$IRQLvl", 1),
			("M$Prior", 1),
			("M$Mode", 1),
			("M$FMgr", 2),
			("M$PDev", 2),
			("M$DevCon", 2),
			(None, 8),
			("M$Opt", 2),
			("M$DTyp", 2),
		]

	# go
	symbolize(textsegea, fields)

	# annotate
	def annotatedecbyte(ea, tab):
		idaapi.op_dec(ea, 0)
		idaapi.set_cmt(ea, tab.get(idaapi.get_byte(ea)), 1)
	annotatedecbyte(idaapi.get_name_ea(BADADDR, "M$Type"), {
		1: "Prgm",
		2: "Sbrtn",
		3: "Multi",
		4: "Data",
		5: "CSDData",
		11: "TrapLib",
		12: "Systm",
		13: "Flmgr",
		14: "Drivr",
		15: "Devic",
	})
	annotatedecbyte(idaapi.get_name_ea(BADADDR, "M$Lang"), {
		1: "Objct",
		2: "ICode",
		3: "PCode",
		4: "CCode",
		5: "CblCode",
		6: "FtrnCode",
	})

	idaapi.doByte(textsegea + header.size - 3, 3)
	idaapi.set_name(textsegea + header.size - 3, "M$CRC", idaapi.SN_CHECK) # coined symbol

	if hmem is not None:
		# make data/bss
		datasegea = ea
		ea = loadseg(".data", ea, hmem, "DATA")

		if hidata is not None:
			# load data
			li.seek(hidata)
			doff = readl(li)
			dlen = readl(li)
			loadbytes(datasegea + doff, dlen, li)

			# symbolize idata in text
			idaapi.set_name(textsegea + hidata, "__data", idaapi.SN_CHECK) # coined symbol
			idaapi.doDwrd(textsegea + hidata, 4)
			idaapi.doDwrd(textsegea + hidata + 4, 4)
			idaapi.doByte(textsegea + hidata + 8, dlen)

	# reloc
	if hirefs is not None:
		idaapi.set_name(textsegea + hirefs, "__irefs", idaapi.SN_CHECK) # coined symbol

		def reloc(tgtsegea, tgtoff, refsegea, refoff=None):
			ea = tgtsegea + tgtoff
			fd = idaapi.fixup_data_t()
			fd.sel = idaapi.setup_selector(refsegea >> 4)
			fd.off = refoff or 0

			# always 32bit reloc
			fd.type = idaapi.FIXUP_OFF32
			get = idaapi.get_long
			put = lambda ea, value: idaapi.put_long(ea, value)

			idaapi.set_fixup(ea, fd)
			# we manually reloc it... need to make disasseble with offset ok
			fd.off += get(ea)
			put(ea, fd.off)

		def reloc_block(relocea, refsegea):
			while True:
				idaapi.doWord(relocea, 2)
				msword = idaapi.get_word(relocea)
				relocea += 2

				idaapi.doWord(relocea, 2)
				count = idaapi.get_word(relocea)
				relocea += 2

				if msword == 0 and count == 0:
					return relocea

				idaapi.doWord(relocea, 2 * count)
				for _ in xrange(count):
					lsword = idaapi.get_word(relocea)
					relocea += 2

					reloc(datasegea, (msword << 16) | lsword, refsegea)

		relocea = textsegea + hirefs
		# data->text
		relocea = reloc_block(relocea, textsegea)
		# data->data
		relocea = reloc_block(relocea, datasegea)

	if header.type in [1, 11, 12]: # Prgm, TrapLib, Systm
		_entryord = 0
		_makecode = 1
		idaapi.add_entry(_entryord, hexec, 'start', _makecode)

	def makeOffsetTable(tabea, base, syms):
		ea = tabea
		known = set()
		for sym in syms:
			idaapi.doWord(ea, 2)
			idaapi.set_cmt(ea, sym, 1)

			w = idaapi.get_full_word(ea)
			if w != 0:
				idaapi.op_offset(ea, 0, idaapi.REF_OFF16 | idaapi.REFINFO_NOBASE, -1, base, 0)
				addr = base + w
				idaapi.add_func(addr, idaapi.BADADDR)
				if addr not in known:
					known.add(addr)
					idaapi.set_name(addr, sym, idaapi.SN_CHECK | idaapi.SN_PUBLIC)
				else:
					# delete duplicated name
					idaapi.set_name(addr, "", 0)

			ea += 2

	if header.type == 13: # Flmgr
		makeOffsetTable(hexec, hexec, ["Create", "Open", "MakDir", "ChgDir", "Delete", "Seek", "Read", "Write", "ReadLn", "WriteLn", "GetStat", "SetStat", "Close"])

	if header.type == 14: # Drivr
		makeOffsetTable(hexec, textsegea, ["Init", "Read", "Write", "GetStat", "SetStat", "TrmNat", "Error"])

	if hexcpt != 0 and header.type in [1, 11, 12, 13, 14]: # Prgm, TrapLib, Systm, Flmgr, Drivr
		_entryord = 1
		_makecode = 1
		idaapi.add_entry(_entryord, hexcpt, 'trapinit', _makecode)

	# TODO: add_entry init/term on header.type==11?

	return 1
