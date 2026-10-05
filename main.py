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
        required = ('bootstrap.sh', 'recover.py', 'probe.py', 'start.py',
                    'requirements-dr.txt', 'requirements-new-vm.txt', 'infisical_server.py','infisical_inventory.py','infisical-deployment.json',
                    'native_agent.py')
        assert all((resources() / name).is_file() for name in required)
        app = App()
        app.update()
        assert len(app.book.tabs()) == 5 and not app.lab.get() and not app.tls.get() and app.native_agent.get()
        for tab in range(5):
            app.nav[tab].invoke()
            app.update()
            assert app.book.index(app.book.select()) == tab
            assert app.page_title.get() == app.titles[tab]
        app._move(-1)
        app.update()
        assert app.book.index(app.book.select()) == 3
        app.geometry('980x700')
        app.update()
        for tab in range(5):
            app.book.select(tab)
            app.update()
            page = app.pages[tab]
            assert page.canvas.winfo_width() > 600
            assert page.canvas.bbox('all') is not None
        app.destroy()
    else:
        main()
