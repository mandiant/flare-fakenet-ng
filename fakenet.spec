# -*- mode: python -*-

block_cipher = None


a = Analysis(['fakenet/fakenet.py'],
             pathex=['fakenet'],
             binaries=None,
             datas=None,
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
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
