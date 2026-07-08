import base64
import tempfile
from pathlib import Path

import embedded_assets

block_cipher = None

ico_path = Path(tempfile.gettempdir()) / "openpagingserver-client-build.ico"
ico_path.write_bytes(base64.b64decode(embedded_assets.APP_ICO))

a = Analysis(
    ["app.py"],
    pathex=["."],
    binaries=[],
    datas=[],
    hiddenimports=["pystray._win32", "miniaudio", "windows_toasts"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="OpenPagingServerDesktop",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ico_path),
)
