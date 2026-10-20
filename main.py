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


def check_package():
    """Validate imports and packaged sources without creating a Tk window."""
    import paramiko
    import yaml
    from recovery_gui.backend import resources, validate_remote_shell_scripts
    from recovery_gui.onboarding import ServiceController
    from recovery_gui.lab_prepare import prepare_lab
    from recovery_gui.onboarding_ssh_api import SSHInfisicalOpener
    from recovery_gui.service_plan import analyze_inputs
    from recovery_gui.ui_onboarding import ServiceOnboardingPanel
    assert paramiko.__version__ and yaml.__version__
    assert ServiceController is not None and ServiceOnboardingPanel is not None
    assert prepare_lab is not None and SSHInfisicalOpener is not None
    validate_remote_shell_scripts()
    for path in resources().glob('*.py'):
        compile(path.read_bytes(), path.name, 'exec')
    assert (resources() / 'service_onboarding.py').is_file()
    plan = analyze_inputs('demo:\n  image: example/demo:latest\n', 'PORT=8080\n').plan
    assert plan.service_name == 'demo' and not plan.private_bindings


if __name__ == '__main__':
    if sys.argv[1:] == ['--check-package']:
        try:
            check_package()
        except Exception:
            # A packaging failure must not open a native error dialog during
            # unattended checks on a computer the user is actively using.
            raise SystemExit(1) from None
    elif sys.argv[1:] == ['--self-test']:
        import paramiko
        from recovery_gui.backend import resources, validate_remote_shell_scripts
        from recovery_gui.ui_state import PHASES, operational_request
        required = ('bootstrap.sh', 'recover.py', 'probe.py', 'start.py',
                    'requirements-dr.txt', 'requirements-new-vm.txt', 'infisical_server.py','infisical_inventory.py','infisical-deployment.json',
                    'native_agent.py', 'test_reset.py', 'aio_snapshot.py', 'runtime_profile.py',
                    'operational_profile.py', 'npm_runtime.py', 'npm_topology.py', 'npm-domain-probe.mjs',
                    'npm-route-probe.mjs', 'tailscale_recovery.py', 'headplane_recovery.py', 'host_dns.py', 'local_endpoints.py',
                    'service_onboarding.py')
        assert all((resources() / name).is_file() for name in required)
        validate_remote_shell_scripts()
        app = App()
        try:
            app.update()
            assert len(app.book.tabs()) == len(app.nav) == len(app.pages) == 4
            assert app.onboarding.controller is not None
            assert set(app.phase_labels) == set(PHASES)
            assert app.infrastructure_verified is False and app.backup_has_aio is None
            assert app.vars['routing_mode'].get() == 'parallel_test'
            assert not app.vars['domain_target_address'].get()
            assert 'dns_server' not in app.vars
            assert app.domain_card.winfo_manager() == 'pack'
            app.var('host').set('192.168.178.20')
            app._use_stack_domain_address()
            assert app.var('domain_target_address').get() == '192.168.178.20'
            app.var('domain_target_address').set('')
            assert not app.supplement_card.winfo_manager()
            assert not {'aio_payload', 'aiostreams_exports', 'aiometadata_exports'} & app.vars.keys()
            point = dict(tag='dr-20261012T010000Z', public_commit='a' * 40, aio_snapshot=True)
            app.events.put(('point', point))
            app.poll()
            assert not app.supplement_card.winfo_manager()
            app.show_error('OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED')
            assert app.supplement_card.winfo_manager() == 'pack'
            app.var('supplemental_inputs').set('fixture.age')
            app.events.put(('point', point))
            app.poll()
            assert app.var('supplemental_inputs').get() == 'fixture.age'
            app.events.put(('point', dict(point, tag='dr-20261012T020000Z', aio_snapshot=False)))
            app.poll()
            assert not app.supplement_card.winfo_manager()
            assert not app.var('supplemental_inputs').get()
            app.show_error('OAUTH_ALLOWLIST_SUPPLEMENT_REQUIRED')
            app.var('supplemental_inputs').set('fixture.age')
            app.events.put(('resumed_selection', dict(point=point, routing_mode='parallel_test',
                                                     domain_target_address='192.0.2.1')))
            app.poll()
            assert not app.supplement_card.winfo_manager()
            assert not app.var('supplemental_inputs').get()
            for action in ('fresh', 'resume'):
                request = operational_request({}, action)
                assert request['aio_mode'] == 'snapshot' and request['native_agent'] is True
                assert request['operational_profile'] is True and request['restart_test'] is False
            for width, height in ((1220, 860), (980, 740)):
                app.geometry(f'{width}x{height}')
                app.update()
                for tab in range(4):
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
