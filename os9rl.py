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

# OS-9/68000 Object/Library File Loader for IDA 6.9 (old!)

import struct
import idaapi

DEBUG = False

# Relocatable Object File format
FORMAT_OBJ = 'ROF(68000): OS-9/68000 Object'
FORMAT_LIB = 'ROF(68000): OS-9/68000 Library'

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
def readd(li):
	return struct.unpack('>I', read(li, 4))[0]

def readdate(li):
	year = readb(li) + 1900
	month = readb(li)
	day = readb(li)
	hour = readb(li)
	minute = readb(li)
	second = readb(li)
	return [year, month, day, hour, minute, second]

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
		# ("magic", readd),
		("type", readb),
		("language", readb),
		("attribute", readb),
		("revision", readb),
		("asmvalid", readw),
		("asversion", readw),
		("date", readdate),
		("edition", readw),
		("bsssize", readd),
		("idatasize", readd),
		("textsize", readd),
		("stacksize", readd),
		("entrypoint", readd),
		("trapinit", readd),
		("remotebsssize", readd),
		("remoteidatasize", readd),
		("debugsize", readd),
		("name", readasciz),
	]

class ExportEntry(LiObject):
	_fields = [
		("name", readasciz),
		("flags", readw),
		("addr", readd),
	]

	def segment(self):
		return {
			0: "bss",
			1: "data",
			4: "text",
			6: "const",
		}[self.flags & 7]

class ExportList(LiObject):
	_fields = [
		("nentries", readw),
		# ("entries", readexport * nentries)
	]

	def __init__(self, li):
		super(ExportList, self).__init__(li)
		self.entries = [ExportEntry(li) for _ in xrange(self.nentries)]

	def __getitem__(self, key):
		return self.entries[key]

class ImportEntry(LiObject):
	_fields = [
		("flags", readw),
		("addr", readd),
	]

	def writesegment(self):
		return "text" if (self.flags & 0x20) != 0 else "data"
	def width(self):
		return 1 << (((self.flags >> 3) & 3) - 1)
	# note: document seems swapped?
	def negative(self):
		return (self.flags & 0x40) != 0
	def relative(self):
		return (self.flags & 0x80) != 0

class Import(LiObject):
	_fields = [
		("name", readasciz),
		("nentries", readw),
		# ("entries", readimport * nentries)
	]

	def __init__(self, li):
		super(Import, self).__init__(li)
		self.entries = [ImportEntry(li) for _ in xrange(self.nentries)]

	def __getitem__(self, key):
		return self.entries[key]

class ImportList(LiObject):
	_fields = [
		("nentries", readw),
		# ("entries", readimport * nentries)
	]

	def __init__(self, li):
		super(ImportList, self).__init__(li)
		self.entries = [Import(li) for _ in xrange(self.nentries)]

	def __getitem__(self, key):
		return self.entries[key]

class RelocEntry(LiObject):
	_fields = [
		("flags", readw),
		("addr", readd),
	]

	def segment(self):
		return {
			0: "bss",
			1: "data",
			4: "text",
			6: "const",
		}[self.flags & 7]
	def writesegment(self):
		return "text" if (self.flags & 0x20) != 0 else "data"
	def width(self):
		return 1 << (((self.flags >> 3) & 3) - 1)
	# note: document seems swapped?
	def negative(self):
		return (self.flags & 0x40) != 0
	def relative(self):
		return (self.flags & 0x80) != 0

class RelocList(LiObject):
	_fields = [
		("nentries", readw),
		# ("entries", readreloc * nentries)
	]

	def __init__(self, li):
		super(RelocList, self).__init__(li)
		self.entries = [RelocEntry(li) for _ in xrange(self.nentries)]

	def __getitem__(self, key):
		return self.entries[key]

def loadpart(li):
	h = Header(li)
	ExportList(li)
	li.seek(h.textsize + h.idatasize + h.remotebsssize + h.debugsize, idaapi.SEEK_CUR)
	ImportList(li)
	RelocList(li)
	li.seek(16, idaapi.SEEK_CUR)

	return h

def accept_file(li, n):
	# only one format accepted
	if n != 0:
		return 0

	li.seek(0)

	if readd(li) != 0xDEADFACE:
		return 0

	# try to read, and find next is available or not
	h = loadpart(li)

	try:
		if readd(li) == 0xDEADFACE:
			return FORMAT_LIB

		# can read but bad magic? maybe not our format.
		return 0
	except EOFError:
		# just end of file means a single object
		return FORMAT_OBJ

class ObjectSelector(idaapi.Choose2):
	def __init__(self, li):
		title = "Choose a object"
		cols = [
			["Offset",  5 | idaapi.Choose2.CHCOL_HEX],
			["Name",   16 | idaapi.Choose2.CHCOL_PLAIN],
			["Date",   19 | idaapi.Choose2.CHCOL_PLAIN],
			["Size",    5 | idaapi.Choose2.CHCOL_HEX],
		]
		idaapi.Choose2.__init__(self, title, cols)
		self.files = []
		while True:
			try:
				offset = li.tell()
				if readd(li) != 0xDEADFACE:
					# unexcepted...
					break
				header = loadpart(li)
				size = li.tell() - offset
				self.files.append({
					"offset": offset,
					"size": size,
					"header": header,
				})
			except EOFError:
				break

	def OnGetSize(self):
		return len(self.files)

	def OnGetLine(self, n):
		file = self.files[n]
		return [
			hex(file["offset"]),
			file["header"].name,
			"%04d-%02d-%02d %02d:%02d:%02d" % tuple(file["header"].date),
			hex(file["size"]),
		]

	def OnClose(self):
		pass

	def show(self):
		i = self.Show(True)
		if i == -1:
			return None
		else:
			return self.files[i]

def load_file(li, neflags, format):
	# hey wrong man
	if format not in [FORMAT_OBJ, FORMAT_LIB]:
		return 0

	# requires 68000 processor module. (should be 68070 for CD-i)
	idaapi.set_processor_type('68000', SETPROC_ALL | SETPROC_FATAL)

	# rewind
	li.seek(0)

	# choose file if library
	# note: extract_module_from_archive is for specific, not customizable...
	if format == FORMAT_LIB:
		file = ObjectSelector(li).show()
		if file == None:
			# cancel
			return 0
		li.seek(file["offset"])

	if readd(li) != 0xDEADFACE:
		raise RuntimeError('Wrong magic??')
	header = Header(li)
	exports = ExportList(li)
	# streaming loadseg is impossible because allocating extra in text requires imports that is placed after text
	textpos = li.tell()
	li.seek(header.textsize, idaapi.SEEK_CUR)
	idatapos = li.tell()
	li.seek(header.idatasize, idaapi.SEEK_CUR)
	# XXX: skip unsupported
	li.seek(header.remotebsssize, idaapi.SEEK_CUR)
	li.seek(header.debugsize, idaapi.SEEK_CUR)
	imports = ImportList(li)
	relocs = RelocList(li)
	li.seek(16, idaapi.SEEK_CUR)

	# making segments
	ea = 0
	segeas = {}

	segeas["text"] = ea
	li.seek(textpos)
	# ea = loadseg(".text", ea, header.textsize, "CODE", li)
	# allocate extra area (and pre-enumerate) to emulate linking relative imports
	importsymintext = {}
	textextra = 0
	for sym in imports:
		for ent in sym.entries:
			if ent.writesegment() == "text" and ent.width() == 2 and ent.relative():
				importsymintext[sym.name] = header.textsize + textextra
				textextra += 2
				break
	ea = loadseg(".text", ea, header.textsize + textextra, "CODE")
	loadbytes(segeas["text"], header.textsize, li)

	li.seek(idatapos)
	segeas["data"] = ea
	ea = loadseg(".data", ea, header.idatasize, "DATA", li)

	segeas["bss"] = ea
	ea = loadseg(".bss", ea, header.bsssize, "DATA")

	segeas["const"] = ea
	ea = loadseg("ABS", ea, sum([4 for sym in exports if sym.segment() == "const"]), "CONST")

	# label export symbols
	constea = segeas["const"]
	for sym in exports.entries:
		if sym.segment() == "const":
			idaapi.put_long(constea, sym.addr)
			idaapi.doDwrd(constea, 4)
			idaapi.set_name(constea, sym.name, idaapi.SN_CHECK | idaapi.SN_PUBLIC)
			constea += 4
		else:
			idaapi.set_name(segeas[sym.segment()] + sym.addr, sym.name, idaapi.SN_CHECK | idaapi.SN_PUBLIC)

	def reloc(tgtsegea, tgtoff, refsegea, refoff, width, relative):
		ea = tgtsegea + tgtoff
		fd = idaapi.fixup_data_t()
		fd.sel = idaapi.setup_selector(refsegea >> 4)
		fd.off = refoff or 0
		# offset and mark type
		if width == 1:
			fd.type = idaapi.FIXUP_OFF8
			get = idaapi.get_byte
			put = lambda ea, value: idaapi.put_byte(ea, value & 0xFF)
		elif width == 2:
			fd.type = idaapi.FIXUP_OFF16
			get = idaapi.get_word
			put = lambda ea, value: idaapi.put_word(ea, value & 0xFFFF)
		else: # if width == 4:
			fd.type = idaapi.FIXUP_OFF32
			get = idaapi.get_long
			put = lambda ea, value: idaapi.put_long(ea, value)
		idaapi.set_fixup(ea, fd)
		# we manually reloc it... need to make disasseble with offset ok
		fd.off += get(ea)
		put(ea, fd.off if not relative else ((refsegea + refoff) - (tgtsegea + tgtoff)))

	# we do segment-reloc then import-symbol(-reloc) to simplify following case:
	#      move.l #0-(x+2)+importsym, d0  <-- segment-reloc +TEXT.l  <-- import-symbol importsym TEXT.l
	#   x: jsr (pc, d0.l)

	# make fixup (for auto make offset and relocation-enabled)
	for ent in relocs.entries:
		# XXX: special treatment for text->+TEXT (I don't understand this yet, just temporal fix)
		#      maybe patch `segment_base - "long"`? but that is bad for import.
		if ent.negative() and ent.writesegment() == "text" and ent.segment() == "text" and ent.width() == 4:
			relea = segeas[ent.writesegment()] + ent.addr
			idaapi.put_long(relea, idaapi.get_long(relea) + ent.addr + 6) # 6 for reloc itself and first word of "jsr".

		reloc(segeas[ent.writesegment()], ent.addr, segeas[ent.segment()], None, ent.width(), ent.relative())

	# make extern (import) symbols
	undefsegea = ea
	# first, allocate extern symbols' EA and non-extern symbols.
	_use32 = 1
	_align = idaapi.saRelByte # TODO what should be?
	_comb = idaapi.scPub # TODO ditto
	loadseg("UNDEF", ea, 4 * len(imports.entries), "XTRN")
	# making name and extern data.
	# note: put_long must be after addseg... troublesome.
	for sym in imports.entries:
		_dummyvalue = 1
		idaapi.put_long(ea, _dummyvalue) # some long
		idaapi.doDwrd(ea, 4) # manual makeDword required; or strange empty lines produced...
		idaapi.set_name(ea, sym.name, idaapi.SN_CHECK)

		# make also in text (pre-allocated) for resolving bsr
		if sym.name in importsymintext:
			extea = segeas["text"] + importsymintext[sym.name]
			idaapi.doWord(extea, 2) # just make word for avoid becoming code
			idaapi.set_name(extea, "__" + sym.name, idaapi.SN_CHECK)

		# relocate here
		for ent in sym.entries:
			if ent.writesegment() == "text" and ent.width() == 2 and ent.relative():
				# bsr
				reloc(segeas[ent.writesegment()], ent.addr, segeas["text"], importsymintext[sym.name], ent.width(), ent.relative())
			else:
				reloc(segeas[ent.writesegment()], ent.addr, undefsegea, ea - undefsegea, ent.width(), ent.relative())

		ea += 4

	if header.type != 0:
		_entryord = 0
		_makecode = 1
		idaapi.add_entry(_entryord, header.entrypoint, 'start', _makecode)

	if header.trapinit != 0xFFFFffff:
		_entryord = 1
		_makecode = 1
		idaapi.add_entry(_entryord, header.trapinit, 'trapinit', _makecode)

	idaapi.add_pgm_cmt("name: %s\ndate: %04d-%02d-%02d %02d:%02d:%02d" % ((header.name,) + tuple(header.date)))

	return 1
