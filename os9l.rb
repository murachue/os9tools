# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

require 'kaitai/struct/struct'

unless Gem::Version.new(Kaitai::Struct::VERSION) >= Gem::Version.new('0.9')
  raise "Incompatible Kaitai Struct Ruby API: 0.9 or later is required, but you have #{Kaitai::Struct::VERSION}"
end

class Os9l < Kaitai::Struct::Struct
  def initialize(_io, _parent = nil, _root = self)
    super(_io, _parent, _root)
    _read
  end

  def _read
    @objects = []
    i = 0
    while not @_io.eof?
      @objects << Obj.new(@_io, self, @_root)
      i += 1
    end
    self
  end
  class Sym2a < Kaitai::Struct::Struct
    def initialize(_io, _parent = nil, _root = self)
      super(_io, _parent, _root)
      _read
    end

    def _read
      @flags = @_io.read_u2be
      @addr = @_io.read_u4be
      self
    end
    attr_reader :flags
    attr_reader :addr
  end
  class Sym < Kaitai::Struct::Struct
    def initialize(_io, _parent = nil, _root = self)
      super(_io, _parent, _root)
      _read
    end

    def _read
      @name = (@_io.read_bytes_term(0, false, true, true)).force_encoding("ascii")
      @flags = @_io.read_u2be
      @addr = @_io.read_u4be
      self
    end
    attr_reader :name
    attr_reader :flags
    attr_reader :addr
  end
  class Sym2 < Kaitai::Struct::Struct
    def initialize(_io, _parent = nil, _root = self)
      super(_io, _parent, _root)
      _read
    end

    def _read
      @name = (@_io.read_bytes_term(0, false, true, true)).force_encoding("ascii")
      @nentries = @_io.read_u2be
      @entries = Array.new(nentries)
      (nentries).times { |i|
        @entries[i] = Sym2a.new(@_io, self, @_root)
      }
      self
    end
    attr_reader :name
    attr_reader :nentries
    attr_reader :entries
  end
  class Obj < Kaitai::Struct::Struct
    def initialize(_io, _parent = nil, _root = self)
      super(_io, _parent, _root)
      _read
    end

    def _read
      @magic = @_io.read_u4be
      @x1 = @_io.read_u4be
      @niner = @_io.read_u4be
      @date = Date6.new(@_io, self, @_root)
      @x4 = @_io.read_u2be
      @x5 = @_io.read_u4be
      @idatasize = @_io.read_u4be
      @textsize = @_io.read_u4be
      @x8 = @_io.read_u4be
      @x9 = @_io.read_u4be
      @xa = @_io.read_u4be
      @xb = @_io.read_u4be
      @xc = @_io.read_u4be
      @xd = @_io.read_u4be
      @name = (@_io.read_bytes_term(0, false, true, true)).force_encoding("ascii")
      @nexportsyms = @_io.read_u2be
      @exportsyms = Array.new(nexportsyms)
      (nexportsyms).times { |i|
        @exportsyms[i] = Sym.new(@_io, self, @_root)
      }
      @text = @_io.read_bytes(textsize)
      @idata = @_io.read_bytes(idatasize)
      @nimportsyms = @_io.read_u2be
      @importsyms = Array.new(nimportsyms)
      (nimportsyms).times { |i|
        @importsyms[i] = Sym2.new(@_io, self, @_root)
      }
      @nreloc = @_io.read_u2be
      @reloc = Array.new(nreloc)
      (nreloc).times { |i|
        @reloc[i] = Sym2a.new(@_io, self, @_root)
      }
      @nsyms3 = @_io.read_u2be
      @syms3 = Array.new(nsyms3)
      (nsyms3).times { |i|
        @syms3[i] = Sym2.new(@_io, self, @_root)
      }
      @nz = @_io.read_u2be
      @z = Array.new(nz)
      (nz).times { |i|
        @z[i] = Sym2a.new(@_io, self, @_root)
      }
      @zz1 = @_io.read_u4be
      @zz2 = @_io.read_u4be
      @zz3 = @_io.read_u4be
      self
    end
    attr_reader :magic
    attr_reader :x1
    attr_reader :niner
    attr_reader :date
    attr_reader :x4
    attr_reader :x5
    attr_reader :idatasize
    attr_reader :textsize
    attr_reader :x8
    attr_reader :x9
    attr_reader :xa
    attr_reader :xb
    attr_reader :xc
    attr_reader :xd
    attr_reader :name
    attr_reader :nexportsyms
    attr_reader :exportsyms
    attr_reader :text
    attr_reader :idata
    attr_reader :nimportsyms
    attr_reader :importsyms
    attr_reader :nreloc
    attr_reader :reloc
    attr_reader :nsyms3
    attr_reader :syms3
    attr_reader :nz
    attr_reader :z
    attr_reader :zz1
    attr_reader :zz2
    attr_reader :zz3
  end
  class Date6 < Kaitai::Struct::Struct
    def initialize(_io, _parent = nil, _root = self)
      super(_io, _parent, _root)
      _read
    end

    def _read
      @rawyear = @_io.read_u1
      @month = @_io.read_u1
      @day = @_io.read_u1
      @hour = @_io.read_u1
      @minute = @_io.read_u1
      @second = @_io.read_u1
      self
    end
    def year
      return @year unless @year.nil?
      @year = (1900 + rawyear)
      @year
    end
    attr_reader :rawyear
    attr_reader :month
    attr_reader :day
    attr_reader :hour
    attr_reader :minute
    attr_reader :second
  end
  attr_reader :objects
end
