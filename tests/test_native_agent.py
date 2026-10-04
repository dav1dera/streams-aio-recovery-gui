import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'remote'))
import native_agent as agent


class NativeAgentSafety(unittest.TestCase):
    def test_recovered_env_mapping_rebased_and_hooks_removed(self):
        obj={'templates':[{'destination-path':'/home/pi/streams-aio/.secrets/comet.env',
                            'template-content':'{{ listSecrets "project" "prod" "/comet" }}',
                            'config':{'execute':{'command':'private-old-hook'}}}]}
        rows=agent.private_templates(obj,Path('/private'),Path('/home/ubuntu/streams-aio'))
        self.assertEqual(rows[0]['destination-path'],str(Path('/home/ubuntu/streams-aio/.secrets/comet.env').absolute()))
        self.assertEqual(rows[0]['config'],{'polling-interval':'60s'})
        self.assertNotIn('private-old-hook',json.dumps(rows))
        self.assertIn('execute',obj['templates'][0]['config'])

    def test_mutable_app_configuration_is_not_watched(self):
        obj={'templates':[{'destination-path':'/home/pi/streams-aio/.secrets/comet.env','template-content':'private-canary'},
                          {'destination-path':'/home/pi/streams-aio/data/honey/data/config/config.json',
                           'template-content':'private-canary'}]}
        rows=agent.private_templates(obj,Path('/private'),Path('/home/pi/streams-aio'))
        self.assertEqual(len(rows),1)
        self.assertTrue(rows[0]['destination-path'].endswith(str(Path('.secrets/comet.env'))))

    def test_escape_and_duplicate_destinations_refused(self):
        for destination in ('/etc/passwd','/home/pi/streams-aio/.secrets/../../public.txt'):
            with self.assertRaises(agent.Refused):
                agent.private_templates({'templates':[{'destination-path':destination,'template-content':'canary'}]},
                                        Path('/private'),Path('/home/pi/streams-aio'))
        row={'destination-path':'/home/pi/streams-aio/.secrets/private.env','template-content':'canary'}
        with self.assertRaisesRegex(agent.Refused,'AGENT_DUPLICATE_DESTINATION'):
            agent.private_templates({'templates':[row,row]},Path('/private'),Path('/home/pi/streams-aio'))

    def test_ssh_unit_has_no_lan_listener_or_host_key_bypass(self):
        unit=agent.tunnel_unit(Path('/home/pi/.local/share/recovery'),'pi','vm.example.invalid',22,80).decode()
        self.assertIn('127.0.0.1:18180:127.0.0.1:80',unit)
        self.assertIn('StrictHostKeyChecking=yes',unit)
        self.assertIn('ExitOnForwardFailure=yes',unit)
        self.assertIn('BatchMode=yes',unit)
        self.assertNotIn('0.0.0.0',unit)
        self.assertNotIn('password',unit.lower())

    def test_untrusted_host_cannot_inject_unit_settings(self):
        for host in ('vm\nExecStart=secret','vm;cat /private','vm user','-oProxyCommand=bad'):
            with self.assertRaises(agent.Refused):
                agent.tunnel_unit(Path('/private'),'pi',host,22,80)

    def test_agent_binary_is_pinned_to_current_source_version(self):
        self.assertEqual(agent.VERSION,'0.43.137')
        self.assertEqual(len(agent.CLI_SHA256),64)
        self.assertIn('/v0.43.137/',agent.CLI_URL)
        self.assertNotIn('/latest/',agent.CLI_URL)


if __name__=='__main__':
    unittest.main()
