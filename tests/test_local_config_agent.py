"""A recovered local map must remain available to the next backup."""
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'remote'))
import native_agent as agent


class LocalAgentInputs(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.backup = self.root/'backup'
        self.backup.mkdir()
        self.plan = {'required_values':['/stack-network/DEFAULT_SUBNET']}

    def test_legacy_archive_does_not_create_local_settings(self):
        output = self.root/'output'
        agent.preserve_local_inputs(self.backup,self.plan,output)
        self.assertFalse(output.exists())

    def fixture(self, provenance=True):
        directory = self.backup/'etc/infisical'
        directory.mkdir(parents=True)
        path = directory/'local-stack-config.json'
        path.write_text(json.dumps({'schema':1,'values':{'/stack-network/DEFAULT_SUBNET':'10.10.0.0/24'}}))
        path.chmod(0o600)
        if provenance:
            path = directory/'local-stack-agent-source.json'
            path.write_text(json.dumps({'schema':1,'templates':{
                '.secrets/aiostreams.env':'original-streams-template',
                '.secrets/aiometadata.env':'original-metadata-template'}}))
            path.chmod(0o600)

    def test_missing_provenance_refused_before_creating_destination(self):
        self.fixture(provenance=False)
        with self.assertRaises(agent.Refused):
            agent.preserve_local_inputs(self.backup,self.plan,self.root/'output')
        self.assertFalse((self.root/'output').exists())

    @unittest.skipUnless(os.name=='posix' and hasattr(os,'geteuid') and os.geteuid()==0,
                         'Requires real root-owned private files')
    def test_both_files_survive_with_private_permissions_and_conflicts_refused(self):
        self.fixture()
        output = self.root/'output'
        agent.preserve_local_inputs(self.backup,self.plan,output)
        agent.preserve_local_inputs(self.backup,self.plan,output)
        for name in ('local-stack-config.json','local-stack-agent-source.json'):
            self.assertEqual((output/name).read_bytes(),(self.backup/'etc/infisical'/name).read_bytes())
            self.assertEqual(stat.S_IMODE((output/name).stat().st_mode),0o600)
            self.assertEqual((output/name).stat().st_uid,0)
        (output/'local-stack-config.json').write_text('foreign-existing-config')
        with self.assertRaisesRegex(agent.Refused,'AGENT_EXISTING_INSTALLATION_CHANGED'):
            agent.preserve_local_inputs(self.backup,self.plan,output)
        self.assertEqual((output/'local-stack-config.json').read_text(),'foreign-existing-config')


if __name__=='__main__':
    unittest.main()
