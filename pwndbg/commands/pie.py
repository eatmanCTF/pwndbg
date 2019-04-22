#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import os

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.vmmap
from pwndbg.commands.windbg import dX, ds


def get_exe_name():
    """
    Returns exe name, tries AUXV first which should work fine on both
    local and remote (gdbserver, qemu gdbserver) targets.

    If the value is somehow not present in AUXV, we just fallback to
    local exe filepath.

    NOTE: This might be wrong for remote targets.
    """
    path = pwndbg.auxv.get().get('AT_EXECFN')

    if path is not None:
        # We normalize the path as `AT_EXECFN` might contain e.g. './a.out'
        # so matching it against Page.objfile later on will be wrong;
        # We want just 'a.out'
        return os.path.normpath(path)

    return pwndbg.proc.exe


def translate_addr(offset, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.vmmap.get()))

    if not pages:
        print('There are no memory pages in `vmmap` '
              'for specified address=0x%x and module=%s' % (offset, module))
        return

    first_page = min(pages, key=lambda page: page.vaddr)

    addr = first_page.vaddr + offset

    if not any(addr in p for p in pages):
        print('Offset 0x%x rebased to module %s as 0x%x is beyond module\'s '
              'memory pages:' % (offset, module, addr))
        for p in pages:
            print(p)
        # eatman fix: however, we still get the address
        # return

    return addr


parser = argparse.ArgumentParser()
parser.description = 'Calculate VA of RVA from PIE base.'
parser.add_argument('offset', nargs='?', default=0,
                    help='Offset from PIE base.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def piebase(offset=None, module=None):
    offset = int(offset)
    if not module:
        module = get_exe_name()

    addr = translate_addr(offset, module)

    if addr is not None:
        print('Calculated VA from %s = %#x' % (module, addr))


parser = argparse.ArgumentParser()
parser.description = 'Break at RVA from PIE base.'
parser.add_argument('offset', nargs='?', default=0,
                    help='Offset to add.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def breakrva(offset=None, module=None):
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)

    if addr is not None:
        spec = "*%#x" % (addr)
        gdb.Breakpoint(spec)


@pwndbg.commands.QuietSloppyParsedCommand
@pwndbg.commands.OnlyWhenRunning
def brva(offset=None, module=None):
    """Alias for breakrva."""
    return breakrva(offset, module)


"""
eatman fix
"""

parser = argparse.ArgumentParser()
parser.description = 'Get the RVA of the given VA.'
parser.add_argument('va', nargs='?', default=0,
                    help='VA.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def rva(va, module=None):
    pages = list(filter(lambda page: va in page, pwndbg.vmmap.get()))

    if not pages:
        print('Address 0x%x is not in current pages' % (va))
        return

    first_page = min(pages, key=lambda page: page.vaddr)
    rva = va - first_page.vaddr
    print("Calculated RVA to %s = %#x" % (first_page.objfile, rva))
    

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dbva(offset, count=64, module=None):
    """
    Starting at the specified address, dump N bytes
    (default 64).
    """
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    return dX(1, (addr), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dwva(offset, count=32, module=None):
    """
    Starting at the specified address, dump N words
    (default 32).
    """
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    return dX(2, (addr), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def ddva(offset, count=16, module=None):
    """
    Starting at the specified address, dump N dwords
    (default 16).
    """
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    return dX(4, (addr), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dqva(offset, count=8, module=None):
    """
    Starting at the specified address, dump N qwords
    (default 8).
    """
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    return dX(8, (addr), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dcva(offset, count=8, module=None):
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    return pwndbg.commands.hexdump.hexdump(address=addr, count=count)

ds_parser = argparse.ArgumentParser()
ds_parser.description = 'Dump a string at the specified address.'
ds_parser.add_argument('offset', help='Address to dump')
ds_parser.add_argument('max', type=int, nargs='?', default=256,
                       help='Maximum string length')

@pwndbg.commands.ArgparsedCommand(ds_parser)
@pwndbg.commands.OnlyWhenRunning
def dsva(offset, max, module=None):
    offset = int(offset)
    offset &= pwndbg.arch.ptrmask
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    return ds(addr, max)
