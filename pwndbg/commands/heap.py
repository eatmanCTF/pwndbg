#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import struct

import gdb
import six
import math

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.typeinfo
from pwndbg.eatmanutils import *
from pwndbg.color import generateColorFunction
from pwndbg.color import message


def read_chunk(addr):
    # in old versions of glibc, `mchunk_[prev_]size` was simply called `[prev_]size`
    # to support both versions, we change the new names to the old ones here so that
    # the rest of the code can deal with uniform names
    renames = {
        "mchunk_size": "size",
        "mchunk_prev_size": "prev_size",
    }
    val = pwndbg.typeinfo.read_gdbvalue("struct malloc_chunk", addr)
    return dict({ renames.get(key, key): int(val[key]) for key in val.type.keys() }, value=val)


def format_bin(bins, verbose=False, offset=None):
    main_heap = pwndbg.heap.current
    if offset is None:
        offset = main_heap.chunk_key_offset('fd')

    result = []
    bins_type = bins.pop('type')

    for size in bins:
        b = bins[size]
        count, is_chain_corrupted = None, False

        # fastbins consists of only single linked list
        if bins_type == 'fastbins':
            chain_fd = b
        # tcachebins consists of single linked list and entries count
        elif bins_type == 'tcachebins':
            chain_fd, count = b
        # normal bins consists of double linked list and may be corrupted (we can detect corruption)
        else:  # normal bin
            chain_fd, chain_bk, is_chain_corrupted = b

        if not verbose and (chain_fd == [0] and not count) and not is_chain_corrupted:
            continue

        formatted_chain = pwndbg.chain.format(chain_fd[0], offset=offset)

        if isinstance(size, int):
            size = hex(size)

        if is_chain_corrupted:
            line = message.hint(size) + message.error(' [corrupted]') + '\n'
            line += message.hint('FD: ') + formatted_chain + '\n'
            line += message.hint('BK: ') + pwndbg.chain.format(chain_bk[0], offset=main_heap.chunk_key_offset('bk'))
        else:
            if count is not None:
                line = (message.hint(size) + message.hint(' [%3d]' % count) + ': ').ljust(13)
            else:
                line = (message.hint(size) + ': ').ljust(13)
            line += formatted_chain

        result.append(line)

    if not result:
        result.append(message.hint('empty'))

    return result

def heapdetail(*args):
    start = int(args[0]) if len(args) >= 1 else None
    end = int(args[1]) if len(args) >= 2 else start if start else None
    h(start=start, end=end, detail=True)

def h(addr=None, pwndbgmode=False, start=None, end=None, detail=False):
    """
    Prints out chunks starting from the address specified by `addr`.
    """
    main_heap  = pwndbg.heap.current
    main_arena = main_heap.main_arena
    if main_arena is None:
        return

    page = main_heap.get_heap_boundaries(addr)
    if addr is None:
        addr = page.vaddr

    # Print out all chunks on the heap
    # TODO: Add an option to print out only free or allocated chunks

    # Check if there is an alignment at the start of the heap
    size_t = pwndbg.arch.ptrsize
    first_chunk_size = pwndbg.arch.unpack(pwndbg.memory.read(addr + size_t, size_t))
    if first_chunk_size == 0:
        addr += size_t * 2  # Skip the alignment

    idx = 0
    while addr < page.vaddr + page.memsz:
        output = False
        while True:
            if start is not None and idx < start:
                break
            if end is not None and idx > end:
                break
            output = True
            break
        chunk = malloc_chunk(addr, idx=idx, pwndbgmode=pwndbgmode, output=output, detail=detail) # Prints the chunk
        size = int(chunk['size'])

        # Clear the bottom 3 bits
        size &= ~7
        if size == 0:
            break
        addr += size
        idx += 1

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap_pwndbg(addr=None):
    """
    Prints out chunks starting from the address specified by `addr`.
    """
    h(addr=addr, pwndbgmode=True)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap(mode='all', *args):
    """
    Prints out chunks starting from the address specified by `addr`.
    """
    
    if mode == 'all':
        h()
        return 
    elif 'detail'.find(mode) == 0:
        heapdetail(*args)
        return
    elif 'fastbin'.find(mode) == 0:
        fastbins()
        return
    elif 'bins'.find(mode) == 0:
        if pwndbg.heap.current.has_tcache():
            tcachebins()
        fastbins()
        unsortedbin()
        smallbins()
        largebins()
    elif 'tcache'.find(mode) == 0:
        if pwndbg.heap.current.has_tcache():
            tcachebins()
        return
    else:
        try:
            start = int(mode)
            end = int(args[0])
            h(start=start, end=end)
        except Exception:
            print(message.error('Usage: heap [all/detail/fastbin/tcached/bins]'))
            return

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def arena(addr=None):
    """
    Prints out the main arena or the arena at the specified by address.
    """
    main_heap   = pwndbg.heap.current
    main_arena  = main_heap.get_arena(addr)

    if main_arena is None:
        return

    print(main_arena)


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def arenas():
    """
    Prints out allocated arenas.
    """
    heap = pwndbg.heap.current
    for ar in heap.arenas:
        print(ar)


@pwndbg.commands.ArgparsedCommand('Print malloc thread cache info.')
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def tcache(addr=None):
    """
    Prints out the thread cache.

    Glibc 2.26 malloc introduced per-thread chunk cache. This command prints
    out per-thread control structure of the cache.
    """
    main_heap = pwndbg.heap.current
    tcache = main_heap.get_tcache(addr)

    if tcache is None:
        return

    print(tcache)


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def mp():
    """
    Prints out the mp_ structure from glibc
    """
    main_heap   = pwndbg.heap.current

    print(main_heap.mp)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def top_chunk(addr=None):
    """
    Prints out the address of the top chunk of the main arena, or of the arena
    at the specified address.
    """
    main_heap   = pwndbg.heap.current
    main_arena  = main_heap.get_arena(addr)

    if main_arena is None:
        heap_region = main_heap.get_heap_boundaries()
        if not heap_region:
            print(message.error('Could not find the heap'))
            return

        heap_start = heap_region.vaddr
        heap_end   = heap_start + heap_region.size

        # If we don't know where the main_arena struct is, just iterate
        # through all the heap objects until we hit the last one
        last_addr = None
        addr = heap_start
        while addr < heap_end:
            chunk = read_chunk(addr)
            size = int(chunk['size'])

            # Clear the bottom 3 bits
            size &= ~7

            last_addr = addr
            addr += size
            addr += size
        address = last_addr
    else:
        address = main_arena['top']

    return malloc_chunk(address)

def print_chunk_detail(addr, size):
    def get_type(size):
        return {
        4: pwndbg.typeinfo.uint32,
        8: pwndbg.typeinfo.uint64,
        }[size]
    def enhex(size, value, fill=True):
        value = value & pwndbg.arch.ptrmask
        x = "%x" % abs(value)
        if fill:
            x = x.rjust(size * 2, '0')
        return x
    values = []
    address = addr & pwndbg.arch.ptrmask
    type   = get_type(pwndbg.arch.ptrsize)
    count = int((size & ~7) / pwndbg.arch.ptrsize)

    for i in range(count):
        try:
            gval = pwndbg.memory.poi(type, address + i * pwndbg.arch.ptrsize)
            values.append(int(gval))
        except gdb.MemoryError:
            break

    n_rows = int(math.ceil(count * pwndbg.arch.ptrsize / float(16)))
    row_sz = int(16 / pwndbg.arch.ptrsize)
    rows   = [values[i*row_sz:(i+1)*row_sz] for i in range(n_rows)]
    lines  = []

    repeat_row = None
    appended = False    
    for i, row in enumerate(rows):
        if not row:
            continue
        if row == repeat_row and size > 0x100 and i != len(rows) - 1:
            if not appended:
                lines.append('.' * 6)
                appended = True
            continue
        if i == 0:
            line = [M.get(address), '   ']
        else:
            line = ['0x' + enhex(pwndbg.arch.ptrsize, address + (i*16), fill=False),'   ']
        for value in row:
            line.append(enhex(pwndbg.arch.ptrsize, value))
        lines.append(' '.join(line))
        repeat_row = row
        appended = False    
    print('\n'.join(lines))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def malloc_chunk(addr,idx=None,fake=False,pwndbgmode=False,output=True,detail=False):
    """
    Prints out the malloc_chunk at the specified address.
    """
    main_heap = pwndbg.heap.current

    if not isinstance(addr, six.integer_types):
        addr = int(addr)

    chunk = read_chunk(addr)
    size = int(chunk['size'])
    actual_size = size & ~7
    prev_inuse, is_mmapped, non_main_arena = main_heap.chunk_flags(size)
    arena = None
    if not fake and non_main_arena:
        arena = main_heap.get_heap(addr)['ar_ptr']

    fastbins = [] if fake else main_heap.fastbins(arena)
    if output:
        if pwndbgmode:
            header = M.get(addr)
            if fake:
                header += message.prompt(' FAKE')
            if prev_inuse:
                if actual_size in fastbins:
                    header += message.hint(' FASTBIN')
                else:
                    header += message.hint(' PREV_INUSE')
            if is_mmapped:
                header += message.hint(' IS_MMAPED')
            if non_main_arena:
                header += message.hint(' NON_MAIN_ARENA')
            print(header, chunk["value"])
        elif not detail:
            """
            print format by eatman
            """
            tail = ""
            if fake:
                tail += message.prompt(' FAKE')
            if prev_inuse:
                if actual_size in fastbins:
                    tail += message.hint(' FASTBIN')
                # else:
                tail += message.hint(' PREV_INUSE')
            if is_mmapped:
                tail += message.hint(' IS_MMAPED')
            if non_main_arena:
                tail += message.hint(' NON_MAIN_ARENA')
            def ascii_char(ch):
                if ord(ch) >= 0x20 and ord(ch) < 0x7e:
                    return chr(ord(ch))  # Ensure we return a str
                else:
                    return "."
            show = ""
            if idx is not None:
                show += "[{:03d}] ".format(idx)
            show += M.get(addr)
            show += " SIZE=" + hex(actual_size)
            headersize = pwndbg.arch.ptrsize * 2
            data = addr + headersize
            show += " DATA[" + hex(data)+"]"
            if size >= 0x20:
                bytes = pwndbg.memory.read(data, 0x20, partial=True)
            else:
                bytes = pwndbg.memory.read(data, size, partial=True)

            asciibytes = "".join([ascii_char(c) for c in bytes_iterator(bytes)])
            show += " |" + asciibytes + "|"
            print(show + tail)
        else:
            print_chunk_detail(addr, size)

            
            # if self.is_address(addr+size-0x10)==False:
            #     print(red("overlap at 0x%x -- size=0x%x"%(addr,size)))
            #     return None
            # if self.chunk_inuse(addr):
            #     show += green(' INUSED')
            # if prev_inuse:
            #     show += green(' PREV_INUSE')
            #     if "INUSED" not in show:
            #         show += green(' INUSED')    
    return chunk

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def bins(addr=None, tcache_addr=None):
    """
    Prints out the contents of the tcachebins, fastbins, unsortedbin, smallbins, and largebins from the
    main_arena or the specified address.
    """
    if pwndbg.heap.current.has_tcache():
        tcachebins(tcache_addr)
    fastbins(addr)
    unsortedbin(addr)
    smallbins(addr)
    largebins(addr)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def fastbins(addr=None, verbose=True):
    """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    fastbins  = main_heap.fastbins(addr)

    if fastbins is None:
        return

    formatted_bins = format_bin(fastbins, verbose)

    print(C.banner('fastbins'))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def unsortedbin(addr=None, verbose=True):
    """
    Prints out the contents of the unsorted bin of the main arena or the
    arena at the specified address.
    """
    main_heap   = pwndbg.heap.current
    unsortedbin = main_heap.unsortedbin(addr)

    if unsortedbin is None:
        return

    formatted_bins = format_bin(unsortedbin, verbose)

    print(C.banner('unsortedbin'))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def smallbins(addr=None, verbose=False):
    """
    Prints out the contents of the small bin of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    smallbins = main_heap.smallbins(addr)

    if smallbins is None:
        return

    formatted_bins = format_bin(smallbins, verbose)

    print(C.banner('smallbins'))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def largebins(addr=None, verbose=False):
    """
    Prints out the contents of the large bin of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    largebins = main_heap.largebins(addr)

    if largebins is None:
        return

    formatted_bins = format_bin(largebins, verbose)

    print(C.banner('largebins'))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def tcachebins(addr=None, verbose=False):
    """
    Prints out the contents of the bins in current thread tcache or in tcache
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    tcachebins = main_heap.tcachebins(addr)

    if tcachebins is None:
        return

    formatted_bins = format_bin(tcachebins, verbose, offset = main_heap.tcache_next_offset)

    print(C.banner('tcachebins'))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def find_fake_fast(addr, size):
    """
    Finds candidate fake fast chunks that will overlap with the specified
    address. Used for fastbin dups and house of spirit
    """
    main_heap = pwndbg.heap.current
    max_fast = main_heap.global_max_fast
    fastbin  = main_heap.fastbin_index(int(size))
    start    = int(addr) - int(max_fast)
    mem      = pwndbg.memory.read(start, max_fast, partial=True)

    fmt = {
        'little': '<',
        'big': '>'
    }[pwndbg.arch.endian] + {
        4: 'I',
        8: 'Q'
    }[pwndbg.arch.ptrsize]

    print(C.banner("FAKE CHUNKS"))
    for offset in range(max_fast - pwndbg.arch.ptrsize):
        candidate = mem[offset:offset + pwndbg.arch.ptrsize]
        if len(candidate) == pwndbg.arch.ptrsize:
            value = struct.unpack(fmt, candidate)[0]

            if main_heap.fastbin_index(value) == fastbin:
                malloc_chunk(start+offset-pwndbg.arch.ptrsize,fake=True)


vis_heap_chunks_parser = argparse.ArgumentParser(description='Visualize heap chunks at the specified address')
vis_heap_chunks_parser.add_argument('address', help='Start address')
vis_heap_chunks_parser.add_argument('count', nargs='?', default=2,
                    help='Number of chunks to visualize')

@pwndbg.commands.ArgparsedCommand(vis_heap_chunks_parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def vis_heap_chunks(address, count):
    address = int(address)
    main_heap = pwndbg.heap.current
    main_arena = main_heap.get_arena()
    top_chunk = int(main_arena['top'])

    unpack = pwndbg.arch.unpack

    cells_map = {}
    chunk_id = 0
    ptr_size = pwndbg.arch.ptrsize
    while chunk_id < count:
        prev_size = unpack(pwndbg.memory.read(address, ptr_size))
        current_size = unpack(pwndbg.memory.read(address+ptr_size, ptr_size))
        real_size = current_size & ~main_heap.malloc_align_mask
        prev_inuse = current_size & 1
        stop_addr = address + real_size

        while address < stop_addr:
            assert address not in cells_map
            cells_map[address] = chunk_id
            address += ptr_size

        if prev_inuse:
            cells_map[address - real_size] -= 1

        chunk_id += 1

        # we reached top chunk, add it's metadata and break
        if address >= top_chunk:
            cells_map[address] = chunk_id
            cells_map[address+ptr_size] = chunk_id
            break

    # TODO: maybe print free chunks in bold or underlined
    color_funcs = [
        generateColorFunction("yellow"),
        generateColorFunction("cyan"),
        generateColorFunction("purple"),
        generateColorFunction("green"),
        generateColorFunction("blue"),
    ]

    addrs = sorted(cells_map.keys())

    printed = 0
    out = ''

    for addr in addrs:
        if printed % 2 == 0:
            out += "\n0x%x:" % addr

        cell = unpack(pwndbg.memory.read(addr, ptr_size))
        cell_hex = '\t0x{:0{n}x}'.format(cell, n=ptr_size*2)

        chunk_idx = cells_map[addr]
        color_func_idx = chunk_idx % len(color_funcs)
        color_func = color_funcs[color_func_idx]

        out += color_func(cell_hex)

        printed += 1

    if top_chunk in addrs:
        out += "\t <-- Top chunk"

    print(out)
