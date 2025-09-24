# -*- mode: python ; coding: utf-8 -*-

import os
from pathlib import Path

# Agent dizinini bul
agent_dir = Path(__file__).parent.absolute()
zap_dir = agent_dir / "zap"

# ZAP dosyalarını topla
zap_files = []
if zap_dir.exists():
    for root, dirs, files in os.walk(zap_dir):
        for file in files:
            file_path = os.path.join(root, file)
            # PyInstaller için relative path
            rel_path = os.path.relpath(file_path, agent_dir)
            zap_files.append((file_path, rel_path))

# Ana executable için konfigürasyon
a = Analysis(
    ['agent-simple.py'],
    pathex=[str(agent_dir)],
    binaries=[],
    datas=[
        # ZAP dosyalarını dahil et
        *[(str(Path(src).parent), str(Path(dst).parent)) for src, dst in zap_files],
    ],
    hiddenimports=[
        'requests',
        'psutil',
        'websockets',
        'asyncio',
        'json',
        'logging',
        'subprocess',
        'threading',
        'uuid',
        'datetime',
        'time',
        'os',
        'sys',
        'shutil',
        'platform',
        'pathlib',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

# ZAP executable'larını binary olarak ekle
zap_binaries = []
if zap_dir.exists():
    for root, dirs, files in os.walk(zap_dir):
        for file in files:
            if file.endswith(('.bat', '.cmd', '.sh', '.exe')):
                file_path = os.path.join(root, file)
                rel_path = os.path.relpath(file_path, agent_dir)
                zap_binaries.append((file_path, os.path.dirname(rel_path)))

a.binaries.extend(zap_binaries)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='PentoraSec-Agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
    version_file=None,
)

# Windows için özel ayarlar
if os.name == 'nt':
    exe.version = "2.3.0"
    exe.description = "PentoraSec Desktop Agent with Bundled ZAP"
    exe.company = "PentoraSec"
    exe.product = "PentoraSec Agent"
