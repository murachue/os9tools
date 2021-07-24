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

meta:
  id: os9l
  file-extension:
    - r
    - l
  endian: be
  encoding: ascii
  license: MIT
doc-ref:
  - http://www.icdia.co.uk/microware/77165106.pdf
seq:
  - id: objects
    type: obj
    repeat: eos
types:
  obj:
    seq:
      - id: magic
        type: u4 # 0xdeadface
      - id: type
        type: u1
      - id: language
        type: u1
      - id: attribute
        type: u1
      - id: revision
        type: u1
      - id: asmvalid
        type: u2
      - id: asversion # assembler series
        type: u2
      - id: date
        type: date6
      - id: edition
        type: u2
      - id: bsssize
        type: u4
      - id: idatasize
        type: u4
      - id: textsize
        type: u4
      - id: stacksize
        type: u4
      - id: entrypoint
        type: u4
      - id: trapinit
        type: u4 # FFFFffff=undefined
      - id: remotebsssize
        type: u4
      - id: remoteidatasize
        type: u4
      - id: debugsize
        type: u4
      - id: name
        type: str
        terminator: 0
      - id: nexportsyms
        type: u2
      - id: exportsyms
        type: exportsym
        repeat: expr
        repeat-expr: nexportsyms
      - id: text
        size: textsize
      - id: idata
        size: idatasize
      # remoteidata
      # debug
      - id: nimportsyms
        type: u2
      - id: importsyms
        type: importsym
        repeat: expr
        repeat-expr: nimportsyms
      - id: nreloc
        type: u2
      - id: reloc
        type: reloc
        repeat: expr
        repeat-expr: nreloc
      - id: unknown
        size: 16
    -webide-representation: "{name} {textsize} {idatasize}"
  exportsym:
    seq:
      - id: name
        type: str
        terminator: 0
      - id: flags # 0x100=common 0=.bss 1=.data 4=.text 6=const
        type: u2
      - id: addr
        type: u4
    instances:
      segment:
        enum: segment
        value: flags
    enums:
      segment:
        0: bss
        1: data
        4: text
        6: const
    -webide-representation: "{name} {segment}:{addr}"
  importsym:
    seq:
      - id: name
        type: str
        terminator: 0
      - id: nentries
        type: u2
      - id: entries
        type: importsymentry
        repeat: expr
        repeat-expr: nentries
    -webide-representation: "{name} {entries}"
  importsymentry:
    seq:
      - id: flags
        type: u2  # 0=data 0x20=code, 0x08=1b 0x10=2b 0x18=4b
      - id: addr
        type: u4
    instances:
      segment:
        value: (flags & 0x20) != 0 ? "text" : "data"
      width:
        value: 1 << (((flags >> 3) & 3) - 1)
      widthstr:
        value: width == 1 ? "b" : width == 2 ? "w" : "l"
      relative:
        value: (flags & 0x40) != 0
      relativestr:
        value: relative ? "+" : ""
      negative:
        value: (flags & 0x80) != 0
      negativestr:
        value: negative ? "-" : ""
    -webide-representation: "{negativestr}{relativestr}{segment}:{addr}.{widthstr}"
  reloc:
    seq:
      - id: flags
        type: u2
      - id: addr
        type: u4
    instances:
      relsegment: # where relocate r/w
        value: (flags & 0x20) != 0 ? "text" : "data"
      segmentto: # which relocation offset
        enum: segment
        value: flags & 7
      width:
        value: 1 << (((flags >> 3) & 3) - 1)
      widthstr:
        value: width == 1 ? "b" : width == 2 ? "w" : "l"
      relative:
        value: (flags & 0x40) != 0
      relativestr:
        value: relative ? "+" : ""
      negative:
        value: (flags & 0x80) != 0
      negativestr:
        value: negative ? "-" : ""
    enums:
      segment:
        0: bss
        1: data
        4: text
        # 6: const
    -webide-representation: "{relsegment}:{addr}.{widthstr} -> {negativestr}{relativestr}{segmentto}"
  date6:
    seq:
      - id: rawyear
        type: u1
      - id: month
        type: u1
      - id: day
        type: u1
      - id: hour
        type: u1
      - id: minute
        type: u1
      - id: second #?
        type: u1
    instances:
      year:
        value: 1900 + rawyear
    -webide-representation: "{year:dec}/{month:dec}/{day:dec} {hour:dec}:{minute:dec}:{second:dec}"
