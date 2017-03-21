# -*- mode: python -*-

block_cipher = None


a = Analysis(['fakenet/fakenet.py'],
             pathex=['fakenet'],
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             )

a.binaries = a.binaries - TOC([
 ('sqlite3.dll', None, None),
 ('tcl85.dll', None, None),
 ('tk85.dll', None, None),
 ('_sqlite3', None, None),
 ('_tkinter', None, None)])


driver_files = [('WinDivert64.dll','windivert/WinDivert64.dll', 'BINARY'), ('WinDivert64.sys','windivert/WinDivert64.sys', 'BINARY'),('WinDivert32.dll','windivert/WinDivert32.dll', 'BINARY'), ('WinDivert32.sys','windivert/WinDivert32.sys', 'BINARY')]

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries + driver_files,
          a.zipfiles,
          a.datas,
          icon='resources/fakenet.ico',
          name='fakenet',
          debug=False,
          strip=False,
          upx=True,
          console=True,
          uac_admin=True)

coll = COLLECT(exe,
               strip=False,
               upx=True,
               name='fakenet-dat'
)
