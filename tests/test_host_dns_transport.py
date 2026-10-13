import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from recovery_gui.backend import Failure, SSH, dns_server_address, restore_all, remote_failure_code


class HostDNSTransport(unittest.TestCase):
    def test_dns_failure_survives_closed_metadata_boundary(self):
        self.assertEqual(remote_failure_code(b'{"error":"HOST_DNS_CONFIGURATION_REFUSED"}'),
                         'HOST_DNS_CONFIGURATION_REFUSED')
    def test_dns_choice_is_optional_and_requires_canonical_unicast(self):
        self.assertEqual(dns_server_address(''), '')
        self.assertEqual(dns_server_address(None), '')
        for value in ('192.168.178.12', '1.1.1.1', '2606:4700:4700::1111'):
            self.assertEqual(dns_server_address(value), value)
        for value in ('router', 'http://192.168.178.12', ' 1.1.1.1', '0.0.0.0',
                      '127.0.0.1', '224.0.0.1', '169.254.1.1', 'fe80::1', 'fe80::1%eth0',
                      '::1', '255.255.255.255', ['192.168.178.12']):
            with self.subTest(value=value), self.assertRaisesRegex(Failure, 'HOST_DNS_CONFIGURATION_REFUSED'):
                dns_server_address(value)

    def test_dns_script_uses_authenticated_stdin_and_checks_result(self):
        client = SSH.__new__(SSH)
        client.run = Mock(return_value=b'{"schema":1,"status":"PASS","server":"192.168.178.12"}')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'host_dns.py').write_bytes(b'closed-dns-script')
            with patch('recovery_gui.backend.resources', return_value=root):
                client.configure_host_dns('192.168.178.12')
            client.run.assert_called_once_with(['python3','-B','-','--server','192.168.178.12'],
                sudo=True, input=b'closed-dns-script', timeout=90)
            client.run.reset_mock()
            client.configure_host_dns('')
            client.run.assert_not_called()
            for result in ({'schema':1,'status':'PASS','server':'192.168.178.1'},
                           {'schema':1,'status':'REFUSED','server':'192.168.178.12'}):
                client.run.return_value=json.dumps(result).encode()
                with patch('recovery_gui.backend.resources', return_value=root), \
                     self.assertRaisesRegex(Failure, 'HOST_DNS_CONFIGURATION_FAILED'):
                    client.configure_host_dns('192.168.178.12')

    def test_invalid_dns_never_inspects_or_mutates_destination(self):
        first, second = Mock(), Mock()
        with self.assertRaisesRegex(Failure, 'HOST_DNS_CONFIGURATION_REFUSED'):
            restore_all(first, second, {'dns_server':'127.0.0.1'}, Mock())
        first.assert_not_called()
        self.assertEqual(first.method_calls, [])
        self.assertEqual(second.method_calls, [])

    def test_foreign_destination_never_reaches_dns_change(self):
        first, second = Mock(), Mock()
        request=dict(operational_profile=True,recovery_action='fresh',aio_mode='snapshot',
                     native_agent=True,routing_mode='parallel_test',domain_target_address='192.168.1.20',
                     github_token='fixture',dr_tag='dr-20261013T010000Z',public_commit='a'*40,
                     dns_server='192.168.178.12')
        with patch('recovery_gui.backend.GitHub') as github, \
             patch('recovery_gui.backend.inspect_recovery',side_effect=Failure('FOREIGN_RECOVERY_STATE')):
            github.return_value.point.return_value=dict(aio_snapshot=True,public_commit='a'*40)
            with self.assertRaisesRegex(Failure,'FOREIGN_RECOVERY_STATE'):
                restore_all(first,second,request,Mock(),tls=True)
        first.configure_host_dns.assert_not_called()
        second.configure_host_dns.assert_not_called()

    def test_both_destinations_are_checked_before_dns_and_any_restore(self):
        first, second, bridge = Mock(), Mock(), Mock()
        order=[]
        first.check.side_effect=lambda **kw: order.append('check-stack') or {'machine_id':'one'}
        second.check.side_effect=lambda **kw: order.append('check-infiscal') or {'machine_id':'two'}
        first.configure_host_dns.side_effect=lambda value: order.append('dns-stack')
        second.configure_host_dns.side_effect=lambda value: order.append('dns-infiscal')
        second.prepare.side_effect=lambda *a: order.append('restore-infiscal')
        first.prepare.side_effect=lambda *a: order.append('restore-stack')
        first.start.side_effect=lambda *a: order.append('start')
        bridge.__enter__=Mock(return_value='http://127.0.0.1:12345')
        bridge.__exit__=Mock(return_value=False)
        second.restored_port.return_value=80
        with patch('recovery_gui.backend.APIBridge',return_value=bridge):
            restore_all(first,second,{'native_agent':False,'dns_server':'192.168.178.12'},Mock())
        self.assertEqual(order,['check-stack','check-infiscal','dns-infiscal','dns-stack',
                                'restore-infiscal','restore-stack','start'])

    def test_dns_failure_stops_before_upload_or_database_mutation(self):
        first, second = Mock(), Mock()
        first.check.return_value={'machine_id':'one'}
        second.check.return_value={'machine_id':'two'}
        second.configure_host_dns.side_effect=Failure('HOST_DNS_CONFIGURATION_FAILED')
        with self.assertRaisesRegex(Failure,'HOST_DNS_CONFIGURATION_FAILED'):
            restore_all(first,second,{'native_agent':False,'dns_server':'192.168.178.12'},Mock())
        first.configure_host_dns.assert_not_called()
        first.prepare.assert_not_called()
        second.prepare.assert_not_called()


if __name__ == '__main__':
    unittest.main()
