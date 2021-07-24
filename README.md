# OS-9/68000 Tools

They are files that can be used to analyze OS-9/68000 applications and libraries,
esp. CD-i application files and its toolchain.

## `os9l.ksy` / `os9l.rb`

The [Kaitai Struct](http://kaitai.io/) file for parsing relocatable object(`*.R`) / library(`*.L`) files of OS9C toolchain.

`os9l.rb` is the module compiled for Ruby. (used by `os9lconst.rb`)

## `os9lconst.rb` / `Gemfile` / `Gemfile.lock`

The utility to extract contant values (value of absolute symbols) from a OS9C toolchain library file.

Useful for `USR.L` or `CDISYS.L`.

## `os9rl.py`

The OS-9/68000 Relocatable file or Library file loader for [IDA Pro](https://hex-rays.com/ida-pro/) 6.9 (older version, currently 7.6)

Place this file to /path/to/IDAPro/loaders and you can open a file.

## `os9x.py`

The OS-9/68000 Executable file loader for IDA Pro 6.9.

## `os9_after.py`

The script for IDA Pro, to be run after loading OS-9/68000 Relocatable, Library or Executable file, or after makecode some undefineds.

It makes OS9 calls (`trap #0` + syscall number word) correct, and symbolize .data/.bss.

This script is not perfect, don't work for no .data executables...

# License

MIT
