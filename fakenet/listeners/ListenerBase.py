# Copyright 2025 Google LLC
"""
Utility functions shared across multiple listeners.

This module provides common functionality needed by various FakeNet-NG listeners
including path resolution, security utilities, and data formatting.
"""

import os
import sys


def hexdump_table(data, length=16):
    """Generate hexdump representation of binary data.
    
    Creates a traditional hexdump format with offset, hex bytes, and ASCII representation.
    
    Args:
        data: bytes object to dump
        length: number of bytes per line (default: 16)
        
    Returns:
        list of str, each string representing one line of hexdump output
        
    Example output:
        0000: 48 65 6C 6C 6F 20 77 6F 72 6C 64 21          Hello world!
    """
    hexdump_lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_line = ' '.join(["%02X" % b for b in chunk])
        ascii_line = ''.join([chr(b) if b > 31 and b < 127 else '.' for b in chunk])
        hexdump_lines.append("%04X: %-*s %s" % (i, length*3, hex_line, ascii_line))
    return hexdump_lines


def safe_join(root, path):
    """ 
    Joins a path to a root path, even if path starts with '/', using os.sep
    """ 

    # prepending a '/' ensures '..' does not traverse past the root
    # of the path
    if not path.startswith('/'):
        path = '/' + path
    normpath = os.path.normpath(path)

    return root + normpath

def abs_config_path(path):
    """
    Attempts to return the absolute path of a path from a configuration
    setting.

    First tries just to just take the abspath() of the parameter to see
    if it exists relative to the current working directory.  If that does
    not exist, attempts to find it relative to the 'fakenet' package
    directory. Returns None if neither exists.
    """

    # Try absolute path first
    abspath = os.path.abspath(path)
    if os.path.exists(abspath):
        return abspath

    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        relpath = os.path.join(os.path.dirname(sys.executable), path)
    else:

        # Try to locate the location relative to application path
        relpath = os.path.join(os.path.dirname(os.path.dirname(__file__)), path)

    if os.path.exists(relpath):
        return os.path.abspath(relpath)

    return None
