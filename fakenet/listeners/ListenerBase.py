# Copyright 2025 Google LLC

import logging
import os
import sys


def safe_join(root, path):
    """
    Joins a path to a root path, even if path starts with '/', using os.sep
    """

    # prepending a '/' ensures '..' does not traverse past the root
    # of the path
    if not path.startswith("/"):
        path = "/" + path
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

    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        relpath = os.path.join(os.path.dirname(sys.executable), path)
    else:

        # Try to locate the location relative to application path
        relpath = os.path.join(os.path.dirname(os.path.dirname(__file__)), path)

    if os.path.exists(relpath):
        return os.path.abspath(relpath)

    return None
