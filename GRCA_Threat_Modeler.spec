# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\barec\\Downloads\\GRCA\\desktop_launcher.py'],
    pathex=[],
    binaries=[],
    datas=[('web/static', 'web/static'), ('data/mappings', 'data/mappings'), ('config/profiles', 'config/profiles'), ('data/sample_reports', 'data/sample_reports')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['torch', 'torchvision', 'torchaudio', 'tensorflow', 'onnx', 'onnxruntime', 'matplotlib', 'scipy', 'notebook', 'ipython', 'PIL', 'PyQt5', 'PySide2', 'PySide6', 'ultralytics', 'cv2', 'tensorboard'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='GRCA_Threat_Modeler',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
