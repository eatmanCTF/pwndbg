# -*- coding: utf-8 -*-
"""
Put all functions defined for gdb in here.

This file might be changed into a module in the future.
"""
import six

def bytes_iterator(bytes_):
    """
    Returns iterator over a bytestring. In Python 2, this is just a str. In
    Python 3, this is a bytes.

    Wrap this around a bytestring when you need to iterate to be compatible
    with Python 2 and Python 3.
    """
    raise Exception('Should be overriden')


def _bytes_iterator_py2(bytes_):
    """
    Returns iterator over a bytestring in Python 2.

    Do not call directly, use bytes_iterator instead
    """
    for b in bytes_:
        yield b


def _bytes_iterator_py3(bytes_):
    """
    Returns iterator over a bytestring in Python 3.

    Do not call directly, use bytes_iterator instead
    """
    for b in bytes_:
        yield bytes([b])

if six.PY2:
    # decode_string_escape = _decode_string_escape_py2
    bytes_iterator = _bytes_iterator_py2
    # bytes_chr = _bytes_chr_py2
    # to_binary_string = _to_binary_string_py2
elif six.PY3:
    # decode_string_escape = _decode_string_escape_py3
    bytes_iterator = _bytes_iterator_py3
    # bytes_chr = _bytes_chr_py3
    # to_binary_string = _to_binary_string_py3
else:
    raise Exception("Could not identify Python major version")