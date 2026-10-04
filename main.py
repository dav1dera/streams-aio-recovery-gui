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
                    'requirements-dr.txt', 'requirements-new-vm.txt')
        assert all((resources() / name).is_file() for name in required)
        app = App()
        app.update()
        assert len(app.book.tabs()) == 4 and not app.lab.get() and not app.tls.get()
        for tab in range(4):
            app.book.select(tab)
            app.update()
        app.destroy()
    else:
        main()
