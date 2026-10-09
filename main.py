import os
from pathlib import Path
import sys

# Tcl can resolve Windows directory aliases differently from Python. Relative
# paths also work when the packaged app is launched from a redirected folder.
if getattr(sys, 'frozen', False):
    for name, directory in (('TCL_LIBRARY', '_tcl_data'), ('TK_LIBRARY', '_tk_data')):
        path = Path(sys._MEIPASS) / directory
        try:
            os.environ[name] = os.path.relpath(path)
        except ValueError:  # Executable and working directory on different drives.
            os.environ[name] = str(path)

from recovery_gui.app import App, main

if __name__ == '__main__':
    if sys.argv[1:] == ['--self-test']:
        import paramiko
        from recovery_gui.backend import resources
        from recovery_gui.ui_state import PHASES, operational_request
        required = ('bootstrap.sh', 'recover.py', 'probe.py', 'start.py',
                    'requirements-dr.txt', 'requirements-new-vm.txt', 'infisical_server.py','infisical_inventory.py','infisical-deployment.json',
                    'native_agent.py', 'aio_snapshot.py', 'runtime_profile.py',
                    'operational_profile.py', 'npm_topology.py', 'npm-domain-probe.mjs',
                    'npm-route-probe.mjs')
        assert all((resources() / name).is_file() for name in required)
        app = App()
        try:
            app.update()
            assert len(app.book.tabs()) == len(app.nav) == len(app.pages) == 3
            assert set(app.phase_labels) == set(PHASES)
            assert app.infrastructure_verified is False and app.backup_has_aio is None
            assert app.vars['routing_mode'].get() == 'parallel_test'
            assert not app.vars['domain_target_address'].get()
            for action in ('fresh', 'resume'):
                request = operational_request({}, action)
                assert request['aio_mode'] == 'snapshot' and request['native_agent'] is True
                assert request['operational_profile'] is True and request['restart_test'] is False
            for width, height in ((1220, 860), (980, 740)):
                app.geometry(f'{width}x{height}')
                app.update()
                for tab in range(3):
                    app.nav[tab].invoke()
                    app.update()
                    assert app.book.index(app.book.select()) == tab
                    assert app.page_title.get() == app.titles[tab]
                    page = app.pages[tab]
                    assert page.canvas.winfo_width() > 600
                    assert page.canvas.bbox('all') is not None
        finally:
            app.destroy()
    else:
        main()
