# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files

a = Analysis(
    ['main.py'],
    pathex=['../web-ui-dependencies', '../gui-dependencies', '../test-dependencies'],
    binaries=[],
    datas=[('remote/' + name, 'remote') for name in (
        'bootstrap.sh', 'recover.py', 'probe.py', 'requirements-dr.txt',
        'requirements-new-vm.txt', 'start.py', 'infisical_server.py',
        'infisical_inventory.py', 'infisical-deployment.json',
        'native_agent.py', 'local_config.py', 'runtime_profile.py', 'test_reset.py', 'aio_snapshot.py',
        'operational_profile.py', 'npm_runtime.py', 'npm_topology.py', 'npm-domain-probe.mjs',
        'npm-route-probe.mjs', 'tailscale_recovery.py', 'headplane_recovery.py', 'host_dns.py', 'local_endpoints.py',
        'service_onboarding.py')] + [('recovery_gui/web', 'recovery_gui/web')] + collect_data_files('webview', subdir='js'),
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='StreamsAIO-Recovery',
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
