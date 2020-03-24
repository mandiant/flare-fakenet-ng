Developing for FakeNet-NG
=========================

This guide is divided into two parts:
* Programming
* Source Code and Release Management

Programming
===========

For background on FakeNet-NG internals and architecture, see:
* [FakeNet-NG Internals](internals.md)
* [FakeNet-NG Architecture](architecture.md)

Developing Listeners
--------------------

All listeners must implement just two methods: `start()` and `stop()`. Below is
a sample listener template:


    import logging

    import sys

    import threading
    import socket

    class MyListener():

        def __init__(self, config, name = 'MyListener', logging_level = logging.INFO):
            self.logger = logging.getLogger(name)
            self.logger.setLevel(logging_level)

            self.config = config
            self.name = name

            self.logger.info('Starting...')

            self.logger.debug('Initialized with config:')
            for key, value in config.iteritems():
                self.logger.debug('  %10s: %s', key, value)

        def start(self):

            # Start listener
            # ...

        def stop(self):

            # Stop listener
            # ...

The main listener class `MyListener()` will be provided with a parsed
configuration dictionary containing information such as port to listen on,
protocol, etc. The main listener class will also receive the current listener
instance name and the logging info set by the user.

The only requirement for listener implementation is that you use threading so
that when FakeNet-NG calls the `start()` method, the listener will not block
but spawn a new thread that handles incoming connections.

Another requirement is to ensure that the listener can reliably shutdown when
the `stop()` method is called. For example, make use of connection timeouts to
ensure that the listener does not block on some connection for too long.

Listeners that implement the function `taste(self, data, dport)` will be
considered when packets are directed by the Proxy. The function must return
a score which indicates the likelihood that the Listener handles the
protocol that is contained in the packet.

The logging convention used by FakeNet-NG's listeners is to use the self.logger
object for the output. That way the logging is uniform across the application.
For example to display an error or warning you would use the following:

    self.logger.error("This is an error")
    self.logger.warning("This is a warning")

Finally, after you finish developing the listener, copy it to the `listeners\`
directory and append you module name to `__all__` varialbe in the `listeners\__init__`:

    __all__ = ['RawListener', 'HTTPListener', 'DNSListener', 'SMTPListener', 'MyListener']

At this point you can let the application use the newly created listener by
adding it to the configuration file:

    [MyAwesomeListener]
    Enabled:     True
    Port:        1337
    Protocol:    TCP
    Listener:    MyListener

Developing Diverters
--------------------

FakeNet-NG uses the open source WinDivert library in order to perform the
traffic redirection on Windows Vista+ operating systems. The implementation of
the Windows Diverter is located in
[fakenet\diverters\windows.py](fakenet/diverters/windows.py).

FakeNet-NG uses the open source python-netfilterqueue Cython module to perform
traffic redirection on Linux. The Linux Diverter implementation is located in
[fakenet\diverters\linux.py](fakenet/diverters/linux.py).

Much Windows-specific functionality is implemented in
[fakenet\diverters\winutil.py](fakenet/diverters/winutil.py) using ctypes to
call many of the Windows API functions directly. Likewise, much Linux-specific
functionality is implemented in
[fakenet\diverters\linutil.py](fakenet/diverters/linutil.py).

For detailed information on Diverter internals specific to Linux, see
[internals.md](internals.md).

Source Code and Release Management
==================================

The token `<ver>` indicates the dot-decimal representation of the FakeNet-NG
version number, with no spaces or other punctuation. For example purposes,
version 1.4.3 is used in many cases to exemplify where and how FakeNet-NG
version numbers are to be incorporated in artifacts such as directory names.

Branching, Pull Requests, and Merging
-------------------------------------

FireEye only:
* Create branches directly under the `fireeye/` GitHub repository, not under a
  private fork.

All contributors:
* Pull request comment should bear bulleted list for inclusion in change log.
* New features must be accompanied by updated configuration files under `test/`
  to ensure that `test/test.py` always works.
* New features or fixes should feature a test in `test/test.py` unless it is
  intractable to do so.
* After review, but before merging, at reviewer discretion, either developer or
  reviewer must update the FakeNet-NG version as described below.

FakeNet-NG Versioning
---------------------

As of this writing, the minor version should be incremented any time there is a
merge that includes changes to a code or data file. Exceptions are:
* Modifications to documentation
* Whitespace changes
* Adding, removing, or modifying comments

Expressly included are changes that only modify banners, FakeNet logging
output, etc.

Here is where to update the version:

| File                 | How to update                                        |
|----------------------|------------------------------------------------------|
| `CHANGELOG.txt`      | Increment version, paste pull request comments       |
| `fakenet/fakenet.py` | Update version in banner string                      |
| `setup.py`           | Update `version` parameter to `setup()`              |

Various listeners report `FakeNet/1.3` as their version. As of this writing,
this is disregarded; only the banner, changelog, and setuptools versions are
updated. A future change should be issued to induce listeners to pull their
version number from a central location or not to report a version number at
all.

Building a Stand-Alone Executable (Release Binary) for Windows
--------------------------------------------------------------

The release binary for Windows should be a 32-bit binary, allowing it to be
loaded on both 32-bit systems and 64-bit systems (as a WOW64 process). Ensure
that you install and are using a 32-bit version of Python and its associated
utilities (i.e. `pip`). Use an administrative command prompt where applicable
for installing Python modules for all users.

Pre-requisites:
* Python 2.7 x86 with `pip`
* Visual C++ for Python 2.7 development, available at:
  <https://aka.ms/vcpython27>

Before installing `pyinstaller`, you may wish to take the following steps to
prevent the error `ImportError: No module named PyInstaller`:

```
python -m pip install --upgrade pip
pip install certifi
```

Install FakeNet-NG to acquire most modules:

```
python setup.py install
```

Obtain PyDivert 2.0.9, the only version known to work with FakeNet-NG releases
prepared with PyInstaller:

```
pip install pydivert==2.0.9
```

Install `pyinstaller`:

```
pip install pyinstaller
```

Finally, generate the executable file with PyInstaller:

```
pyinstaller fakenet.spec
```

The stand-alone executable `fakenet.exe` will be available in the `dist/`
directory.

Building a Release Distribution for Windows
-------------------------------------------

The stand-alone executable depends on several files to be able to execute. To
provide a full release distribution, create a release directory named
`fakenet<ver>` (e.g. `fakenet1.4.3`) and copy the following directory and file
structure:

```
fakenet1.4.3\
    +-- LICENSE.txt
    +-- CHANGELOG.txt
    +-- fakenet.exe
    +-- README.md
    |
    +-- docs\
    |   +-- contributors.md
    |   +-- CustomResponse.md
    |
    +-- configs\
    |   +-- default.ini
    |   +-- CustomProviderExample.py
    |   +-- sample_custom_response.ini
    |   +-- sample_raw_response.txt
    |   +-- sample_raw_tcp_response.txt
    |
    +-- defaultFiles\
    |   +-- FakeNet.gif
    |   +-- FakeNet.html
    |   +-- FakeNet.ico
    |   +-- FakeNet.jpg
    |   +-- FakeNetMini.exe
    |   +-- FakeNet.pdf
    |   +-- FakeNet.png
    |   +-- FakeNet.txt
    |   +-- ncsi.txt
    |
    +-- listeners\
        +-- ssl_utils
    		+-- __init__.pyc
    		+-- privkey.pem
    		+-- server.pem
    		+-- ssl_detector.py
```

FireEye only:
* Create a zip file of the release distribution named `fakenet<ver>.zip`, where
  `<ver>` is the dot-decimal version number. For example: `fakenet1.4.3.zip`.
* The top-level directory in the zip file should be `fakenet<ver>` e.g.
  `fakenet1.4.3`.
* Test the distribution before adding it to the appropriate release tag.

Tagging a Release (FireEye only)
--------------------------------

1. Visit <https://github.com/fireeye/flare-fakenet-ng/releases>
2. Click `Draft a new release`
3. Tag version: `v<ver>`, e.g. `v1.4.3`
4. Release title: `FakeNet-NG <ver>`, e.g. `FakeNet-NG 1.4.3`
5. Description: copy the changes from `CHANGELOG.txt` through to the previous
   version
6. Binaries: Attach the release distribution zip file described above

