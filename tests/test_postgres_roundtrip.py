"""Real PG14 round trip using disposable CI containers and synthetic values only."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'remote'))


@unittest.skipUnless(sys.platform=='linux' and os.environ.get('RECOVERY_DOCKER_INTEGRATION')=='1',
                     'Disposable Docker integration runs in Linux CI')
class PostgresRoundTrip(unittest.TestCase):
    def test_source_roles_keys_database_owner_and_data_survive(self):
        import infisical_server as server
        p=server.profile()
        image=p['images']['db']
        suffix=uuid.uuid4().hex[:12]
        source,destination='recovery-source-'+suffix,'recovery-target-'+suffix
        bootstrap='recovery_fixture_'+suffix
        def docker(args,input=None):
            result=subprocess.run(['docker',*args],input=input,capture_output=True,timeout=300)
            self.assertEqual(result.returncode,0,'Synthetic PostgreSQL operation failed')
            return result.stdout
        def ready(name,user):
            for attempt in range(60):
                result=subprocess.run(['docker','exec',name,'psql','-X','-U',user,'-d','postgres','-At','-c','SELECT 1'],
                                      capture_output=True,timeout=5)
                if result.returncode==0 and result.stdout.strip()==b'1':
                    return
                time.sleep(1)
            self.fail('Disposable PostgreSQL did not start')
        try:
            docker(['pull',image])
            docker(['run','-d','--name',source,'--network','none','-e','POSTGRES_USER=infisical',
                    '-e','POSTGRES_DB=infisical','-e','POSTGRES_PASSWORD=synthetic-fixture',image])
            ready(source,'infisical')
            docker(['exec','-i',source,'psql','-X','-v','ON_ERROR_STOP=1','-U','infisical','-d','infisical'],
                   b'CREATE TABLE recovery_fixture (id integer PRIMARY KEY, value text);\n'
                   b"INSERT INTO recovery_fixture VALUES (7,'synthetic-data');\n")
            dump=docker(['exec',source,'pg_dump','-U','infisical','-d','infisical','--format=custom'])
            globals_sql=docker(['exec',source,'pg_dumpall','-U','infisical','--globals-only'])
            # Exact deployed pg_restore client checks a real custom dump header.
            with tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)
                for name,raw in (('infisical-postgres.dump',dump),('infisical-postgres-globals.sql',globals_sql)):
                    path=root/name
                    path.write_bytes(raw)
                    path.chmod(0o600)
                recovery=server.InfisicalRecovery.__new__(server.InfisicalRecovery)
                recovery.deployment=p
                recovery.state={'postgres_bootstrap_user':bootstrap}
                recovery.private=root
                recovery.runtime=lambda:None
                def compose(args,bootstrap=False,input=None):
                    if args==['pull']:
                        return b''
                    if args==['up','-d','--no-deps','db']:
                        docker(['run','-d','--name',destination,'--network','none',
                                '-e','POSTGRES_USER='+recovery.state['postgres_bootstrap_user'],
                                '-e','POSTGRES_DB=postgres','-e','POSTGRES_PASSWORD=synthetic-fixture',image])
                        return b''
                    self.assertEqual(args[:3],['exec','-T','db'])
                    return docker(['exec','-i',destination,*args[3:]],input)
                recovery.compose=compose
                # command() here is the actual pg_restore --list invocation.
                recovery.database()
            sql=("SELECT json_build_object('owner',pg_get_userbyid(datdba),'database',datname) "
                 "FROM pg_database WHERE datname='infisical';")
            info=json.loads(docker(['exec',destination,'psql','-X','-U','infisical','-d','infisical','-At','-c',sql]))
            self.assertEqual(info,dict(owner='infisical',database='infisical'))
            data=docker(['exec',destination,'psql','-X','-U','infisical','-d','infisical','-At','-c',
                         'SELECT id,value FROM recovery_fixture'])
            self.assertEqual(data.strip(),b'7|synthetic-data')
            login=docker(['exec',destination,'psql','-X','-U','infisical','-d','infisical','-At','-c',
                          "SELECT rolcanlogin FROM pg_roles WHERE rolname='"+bootstrap+"'"])
            self.assertEqual(login.strip(),b'f')
        finally:
            for name in (source,destination):
                subprocess.run(['docker','rm','-f','-v',name],capture_output=True,timeout=30)


if __name__=='__main__':
    unittest.main()
