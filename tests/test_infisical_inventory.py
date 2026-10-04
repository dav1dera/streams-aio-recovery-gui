import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('infisical_inventory',
    Path(__file__).resolve().parents[1] / 'remote/infisical_inventory.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def row(service='backend', image='infisical/infisical:v1', project='infisical'):
    return dict(name='/'+service, image=image, image_id='sha256:'+'a'*64,
                service=service, project=project, directory='/home/infiscal/infisical',
                compose_files='/home/infiscal/infisical/docker-compose.yml', mounts=[], ports={})


class InventorySafety(unittest.TestCase):
    def test_inspection_never_requests_env_or_logs(self):
        self.assertNotIn('.Config.Env', module.FORMAT)
        self.assertNotIn('Password', module.FORMAT)
        self.assertNotIn('.Config.Cmd', module.FORMAT)

    def test_unexpected_values_do_not_enter_inventory(self):
        data = row()
        data.update(Env=['TOKEN=private-canary'], Labels={'password':'private-canary'},
                    Config={'Env':['SECRET=private-canary']})
        data['mounts'] = [dict(Type='volume', Source='/var/lib/docker/volumes/db/_data',
                               Destination='/var/lib/postgresql/data', Name='db', RW=True,
                               password='private-canary')]
        data['ports'] = {'8080/tcp':[dict(HostIp='127.0.0.1', HostPort='8080', token='private-canary')]}
        self.assertNotIn('private-canary', json.dumps(module.clean_row(data)))

    def test_multiple_projects_and_missing_labels_refused(self):
        for rows in ([row(), row(project='another')], [row(project=None)],
                     [dict(row(), directory=None)], [row(), row()]):
            with self.assertRaises(module.InventoryRefused):
                module.deployment(rows)

    def test_only_selected_infisical_project_is_reported(self):
        rows = [row(), row('db', 'postgres:16'), row('production', 'other/image', 'other')]
        result = module.deployment(rows)
        self.assertEqual([r['service'] for r in result['services']], ['backend','db'])

    def test_read_errors_hide_raw_command_output(self):
        result = type('Result', (), dict(returncode=1, stdout=b'private-canary', stderr=b'private-canary'))()
        with patch.object(module.subprocess, 'run', return_value=result):
            with self.assertRaises(module.InventoryRefused) as error:
                module.read(['docker','ps'])
        self.assertNotIn('private-canary', str(error.exception))

    def test_inventory_uses_only_metadata_commands(self):
        calls=[]
        def fake(args):
            calls.append(args)
            if args[1]=='ps': return 'a'*12
            if args[1]=='inspect': return json.dumps(row())
            return json.dumps(dict(digests=['infisical/infisical@sha256:'+'b'*64],
                                   os='linux', architecture='amd64'))
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'os-release'
            path.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            result=module.inventory(fake,path)
        self.assertEqual(result['os'],dict(ID='ubuntu',VERSION_ID='24.04'))
        self.assertTrue(all(args[:2] in (['docker','ps'],['docker','inspect'],['docker','image']) for args in calls))


if __name__ == '__main__':
    unittest.main()
