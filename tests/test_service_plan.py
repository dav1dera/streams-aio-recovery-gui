"""Offline synthetic fixtures; no personal values, VM access, or subprocesses."""
import json
import unittest

import yaml

from recovery_gui.service_plan import (PlanFailure, analyze_inputs, append_service,
                                      inspect_inputs, inspect_resources)


class ServicePlanTests(unittest.TestCase):
    def fail_with(self, code, compose, env='', **kwargs):
        with self.assertRaises(PlanFailure) as result:
            analyze_inputs(compose, env, **kwargs)
        self.assertEqual(str(result.exception), code)
        self.assertNotIn('canary', str(result.exception))

    def test_private_selection_is_explicit_and_report_is_value_free(self):
        compose = ('services:\n  demo:\n    image: example/demo:latest\n'
                   '    environment:\n      API_KEY: canary-private-value\n      PORT: 8080\n')
        unselected = analyze_inputs(compose)
        key = next(row for row in unselected.inventory if row.name == 'API_KEY')
        self.assertTrue(key.suggested_private)
        self.assertFalse(key.selected_private)
        result = analyze_inputs(compose, private_names=['API_KEY'])
        self.assertEqual(result.sensitive.as_dict(), {'API_KEY': 'canary-private-value'})
        for text in (repr(result), repr(result.plan), repr(result.sensitive),
                     json.dumps(result.plan.to_public_dict()), json.dumps(result.plan.deployment_payload())):
            self.assertNotIn('canary-private-value', text)
        service = yaml.safe_load(result.plan.compose_fragment)['demo']
        self.assertEqual(service['environment'], {'PORT': 8080})
        self.assertEqual(service['env_file'], ['./data/demo/.env', './.secrets/demo.env'])
        self.assertEqual(result.plan.private_bindings, {'API_KEY': {'folder': '/demo', 'key': 'API_KEY'}})

    def test_comments_and_blank_lines_survive_separation_and_append(self):
        compose = ('services:\n  # New service icon 🌟\n  demo:\n    # image note\n'
                   '    image: example/demo:stable # pinned channel\n\n'
                   '    environment:\n      # public port\n      PORT: 8080\n'
                   '      API_KEY: canary-private-value # assignment note\n'
                   '    restart: unless-stopped\n')
        env = '# Public examples\nTZ=Europe/Rome\n\n# credential field\nAPI_KEY=canary-private-value\n# keep tail\n'
        result = analyze_inputs(compose, env, private_names=['API_KEY'])
        self.assertEqual(result.plan.public_env_text,
                         '# Public examples\nTZ=Europe/Rome\n\n# credential field\n# keep tail\n')
        for comment in ('# New service icon 🌟', '# image note', '# pinned channel', '# public port'):
            self.assertIn(comment, result.plan.compose_fragment)
        existing = ('# Stack header\nname: my-stack\nservices:\n  # old service\n  old:\n'
                    '    image: example/old:latest # keep\n    profiles: [all, base]\n\n'
                    'networks:\n  default:\n    # network note\n    name: keep-network\n')
        actual = result.plan.render_compose(existing)
        self.assertTrue(actual.startswith(existing[:existing.index('networks:')]))
        self.assertTrue(actual.endswith(existing[existing.index('networks:'):]))
        self.assertEqual(yaml.safe_load(actual)['services']['old'], yaml.safe_load(existing)['services']['old'])
        self.assertEqual(result.plan.render_compose(actual), actual)

    def test_supports_service_snippet_and_body_with_explicit_name(self):
        forms = ('services:\n  demo:\n    image: example/demo:latest\n',
                 'demo:\n  image: example/demo:latest\n',
                 'image: example/demo:latest\n')
        for form in forms:
            with self.subTest(form=form):
                result = analyze_inputs(form, service_name='demo')
                self.assertEqual(list(yaml.safe_load(result.plan.compose_fragment)), ['demo'])
                self.assertIn('\n    image:', result.plan.compose_fragment)
        self.fail_with('SERVICE_NAME_REQUIRED', forms[-1])

    def test_inventory_handles_required_placeholder_before_entering_credentials(self):
        compose = 'demo:\n  image: example/demo:latest\n  environment:\n    API_KEY: ${API_KEY:?required}\n'
        inventory = inspect_inputs(compose)
        self.assertEqual(inventory[0].name, 'API_KEY')
        self.assertFalse(inventory[0].has_value)
        self.fail_with('SERVICE_PRIVATE_VALUE_REQUIRED', compose, private_names=['API_KEY'])
        result = analyze_inputs(compose, private_names=['API_KEY'],
                                private_values={'API_KEY': 'canary-$x-{{ hostile }}'})
        self.assertNotIn('environment:', result.plan.compose_fragment)
        self.assertEqual(result.sensitive['API_KEY'], 'canary-$x-{{ hostile }}')
        self.assertNotIn('canary-', repr(result))

    def test_public_interpolation_is_rendered_as_literal_without_shell_or_compose_expansion(self):
        compose = ('demo:\n  image: ${IMAGE:?required}\n  environment:\n'
                   '    VALUE: ${VALUE}\n    PORT: ${PORT:-8080}\n'
                   '  command: ["echo", "${VALUE}", "$$LITERAL"]\n')
        env = "IMAGE=example/demo:latest\nVALUE='public-$not-expanded-$(echo x)-`whoami`'\n"
        result = analyze_inputs(compose, env)
        service = yaml.safe_load(result.plan.compose_fragment)['demo']
        expected = 'public-$$not-expanded-$$(echo x)-`whoami`'
        self.assertEqual(service['environment']['VALUE'], expected)
        self.assertEqual(service['command'][1:], [expected, '$$LITERAL'])
        self.assertEqual(service['environment']['PORT'], '8080')
        self.assertEqual(result.plan.public_env_text, env)

    def test_missing_public_values_and_private_references_outside_environment_are_refused(self):
        self.fail_with('SERVICE_VARIABLE_VALUE_REQUIRED', 'demo:\n  image: ${IMAGE}\n')
        self.fail_with('SERVICE_PRIVATE_INTERPOLATION_OUTSIDE_ENV',
                       'demo:\n  image: example/demo:latest\n  command: ${API_KEY}\n',
                       'API_KEY=canary-private-value\n', private_names=['API_KEY'])

    def test_host_environment_inheritance_is_never_silent(self):
        for environment in ('  environment:\n    PORT:\n', '  environment:\n    - PORT\n'):
            compose = 'demo:\n  image: example/demo:latest\n' + environment
            self.fail_with('SERVICE_VARIABLE_VALUE_REQUIRED', compose)
            result = analyze_inputs(compose, 'PORT=8080\n')
            actual = yaml.safe_load(result.plan.compose_fragment)['demo']['environment']
            self.assertIn(actual, ({'PORT': '8080'}, ['PORT=8080']))
        self.fail_with('SERVICE_ENV_INTERPOLATION_UNSUPPORTED', 'demo:\n  image: example/demo:latest\n',
                       'PUBLIC=${HOST_SECRET}\n')

    def test_environment_list_and_duplicate_keys(self):
        result = analyze_inputs('demo:\n  image: example/demo:latest\n  environment:\n'
                                '    - PORT=8080\n    - API_KEY=canary-private-value\n',
                                private_names=['API_KEY'])
        self.assertEqual(yaml.safe_load(result.plan.compose_fragment)['demo']['environment'], ['PORT=8080'])
        self.fail_with('SERVICE_ENVIRONMENT_INVALID', 'demo:\n  image: example/demo:latest\n'
                       '  environment:\n    - A=1\n    - A=2\n')
        self.fail_with('SERVICE_COMPOSE_DUPLICATE_KEY', 'demo:\n  image: one\n  image: two\n')
        self.fail_with('SERVICE_ENV_DUPLICATE_KEY', 'demo:\n  image: example/demo:latest\n', 'A=1\nA=2\n')

    def test_removing_entire_private_environment_never_removes_next_service_setting(self):
        for environment in ('    API_KEY: canary-private-value\n', '    - API_KEY=canary-private-value\n'):
            compose = ('demo:\n  image: example/demo:latest\n  environment:\n' + environment +
                       '  # restart comment\n  restart: unless-stopped\n  ports: ["8090:80"]\n')
            result = analyze_inputs(compose, private_names=['API_KEY'])
            actual = yaml.safe_load(result.plan.compose_fragment)['demo']
            self.assertEqual(actual['restart'], 'unless-stopped')
            self.assertEqual(actual['ports'], ['8090:80'])
            self.assertNotIn('environment', actual)
            self.assertIn('# restart comment', result.plan.compose_fragment)

    def test_ambiguous_or_executable_yaml_is_closed_without_input_excerpt(self):
        cases = ('services:\n  demo:\n    image: one\ninclude: ./other.yml\n',
                 'demo:\n  image: one\n  extends: ../elsewhere\n',
                 'demo: &demo\n  image: one\n',
                 'demo:\n  image: !!python/object/apply:os.system [canary-private-value]\n',
                 'demo:\n  image: [canary-private-value\n')
        for compose in cases:
            with self.subTest(compose=compose), self.assertRaises(PlanFailure) as error:
                analyze_inputs(compose)
            self.assertNotIn('canary', str(error.exception))

    def test_names_paths_and_credentialed_image_are_refused(self):
        for name in ('../demo', '/demo', 'demo/evil', 'Demo', 'demo;id', 'demo$(id)'):
            with self.subTest(name=name):
                self.fail_with('SERVICE_NAME_INVALID', f'{name}:\n  image: example/demo:latest\n')
        for path in ('../.secrets/demo.env', '../../data/demo/.env', '/etc/passwd', './data/other/.env'):
            with self.subTest(path=path):
                self.fail_with('SERVICE_ENV_FILE_UNSUPPORTED',
                               f'demo:\n  image: example/demo:latest\n  env_file: {path}\n')
        self.fail_with('SERVICE_IMAGE_INVALID', 'demo:\n  image: username:canary-secret@registry/app\n')

    def test_persistent_mounts_include_explicit_backup_restore_coverage(self):
        for source in ('./data/demo/config', './data/other', 'my-volume'):
            with self.subTest(source=source):
                result = analyze_inputs('demo:\n  image: example/demo:latest\n  volumes:\n'
                                        f'    - {source}:/config\n')
                self.assertEqual(result.plan.schema, 2)
                self.assertEqual(result.plan.resources[0]['recovery']['method'], 'stopped_archive')
        for source in ('../data/demo', './data/demo/../../other'):
            self.fail_with('SERVICE_RESOURCE_PATH_INVALID',
                           'demo:\n  image: example/demo:latest\n  volumes:\n' + f'    - {source}:/config\n')
        self.fail_with('SERVICE_DATA_RESOURCE_OUTSIDE_STACK',
                       'demo:\n  image: example/demo:latest\n  volumes: ["/srv/state:/config"]\n')

    def test_tmpfs_is_not_mistaken_for_persistent_data(self):
        result = analyze_inputs('demo:\n  image: example/demo:latest\n  tmpfs:\n    - /tmp\n')
        self.assertEqual(yaml.safe_load(result.plan.compose_fragment)['demo']['tmpfs'], ['/tmp'])

    def test_existing_conflict_is_never_overwritten_and_malformed_root_refused(self):
        result = analyze_inputs('demo:\n  image: example/demo:latest\n')
        with self.assertRaisesRegex(PlanFailure, '^SERVICE_ALREADY_EXISTS$'):
            result.plan.render_compose('services:\n  demo:\n    image: another:latest\n')
        with self.assertRaises(PlanFailure):
            result.plan.render_compose('services: []\n')

    def test_crlf_existing_bytes_are_preserved(self):
        result = analyze_inputs('demo:\n  image: example/demo:latest\n')
        original = '# hello\r\nservices:\r\n  old:\r\n    image: old\r\nnetworks:\r\n  default: {}\r\n'
        rendered = result.plan.render_compose(original)
        self.assertTrue(rendered.startswith(original[:original.index('networks:')]))
        self.assertTrue(rendered.endswith(original[original.index('networks:'):]))
        self.assertNotIn('\n', rendered.replace('\r\n', ''))

    def test_quoted_env_values_are_not_changed_and_selected_assignment_comment_removed(self):
        env = "# keep\nAPI_KEY='canary-pass$abc' # secret field\nPUBLIC='literal # text' # keep\n"
        result = analyze_inputs('demo:\n  image: example/demo:latest\n', env, private_names=['API_KEY'])
        self.assertEqual(result.sensitive['API_KEY'], 'canary-pass$abc')
        self.assertEqual(result.plan.public_env_text, "# keep\nPUBLIC='literal # text' # keep\n")

    def test_known_private_value_repeated_in_comment_is_refused(self):
        self.fail_with('SERVICE_PRIVATE_VALUE_OUTSIDE_ENV',
                       'demo:\n  image: example/demo:latest\n  # canary-private-value\n',
                       'API_KEY=canary-private-value\n', private_names=['API_KEY'])

    def test_compact_private_environment_is_refused_instead_of_losing_public_sibling(self):
        self.fail_with('SERVICE_ENVIRONMENT_FLOW_UNSUPPORTED',
                       'demo:\n  image: example/demo:latest\n  environment: {PORT: 8080, API_KEY: canary-private-value}\n',
                       private_names=['API_KEY'])

    def test_unselected_secret_override_and_control_characters_are_refused(self):
        compose = 'demo:\n  image: example/demo:latest\n  environment:\n    API_KEY: ${API_KEY}\n'
        self.fail_with('SERVICE_PRIVATE_VALUES_INVALID', compose,
                       private_values={'API_KEY': 'canary-private-value'})
        self.fail_with('SERVICE_PRIVATE_VALUES_INVALID', compose, private_names=['API_KEY'],
                       private_values={'API_KEY': 'canary-value\nINJECTED=yes'})
        for value in ("canary'apostrophe", 'canary-final\\', 'canary\tcontrol', 'canary\x7fcontrol'):
            with self.subTest(value=repr(value)):
                self.fail_with('SERVICE_PRIVATE_VALUES_INVALID', compose, private_names=['API_KEY'],
                               private_values={'API_KEY': value})

    def test_fingerprint_excludes_private_values_and_changes_for_public_input(self):
        compose = 'demo:\n  image: example/demo:latest\n  environment:\n    API_KEY: ${API_KEY}\n'
        first = analyze_inputs(compose, 'PORT=80\n', private_names=['API_KEY'], private_values={'API_KEY': 'canary-one'})
        second = analyze_inputs(compose, 'PORT=80\n', private_names=['API_KEY'], private_values={'API_KEY': 'canary-two'})
        third = analyze_inputs(compose, 'PORT=81\n', private_names=['API_KEY'], private_values={'API_KEY': 'canary-two'})
        self.assertEqual(first.plan.fingerprint, second.plan.fingerprint)
        self.assertNotEqual(first.plan.fingerprint, third.plan.fingerprint)

    def test_managed_public_env_file_is_present_even_when_empty(self):
        result = analyze_inputs('demo:\n  image: example/demo:latest\n')
        self.assertEqual(result.plan.public_env_text, '')
        self.assertEqual(yaml.safe_load(result.plan.compose_fragment)['demo']['env_file'], ['./data/demo/.env'])

    def test_escaped_compose_dollar_becomes_one_literal_dollar_in_infisical(self):
        result = analyze_inputs('demo:\n  image: example/demo:latest\n  environment:\n'
                                '    API_KEY: canary-$$literal\n', private_names=['API_KEY'])
        self.assertEqual(result.sensitive['API_KEY'], 'canary-$literal')
        self.assertNotIn('canary', json.dumps(result.plan.deployment_payload()))


class ServiceBundleTests(unittest.TestCase):
    COMPOSE = ("services:\n  web:\n    image: example/web:latest\n"
               "    environment:\n      API_KEY: ${API_KEY:?required}\n"
               "    volumes: [./data/web/public/config:/app/config:ro]\n"
               "    networks: [monitoring]\n"
               "  metrics:\n    image: example/metrics:latest\n"
               "    environment:\n      API_KEY: ${API_KEY:?required}\n"
               "    volumes: [/var/run/docker.sock:/socket:ro, metrics-state:/state]\n"
               "    networks: [monitoring]\n"
               "volumes:\n  metrics-state: {}\n"
               "networks:\n  monitoring: {}\n")

    def test_multi_service_credentials_are_global_unique_and_value_free(self):
        rows = inspect_inputs(self.COMPOSE)
        self.assertEqual([row.name for row in rows], ['WEB__API_KEY', 'METRICS__API_KEY'])
        resources = inspect_resources(self.COMPOSE)
        self.assertEqual(len(resources), 3)
        result = analyze_inputs(self.COMPOSE, private_names=[row.name for row in rows],
                                private_values={'WEB__API_KEY': 'canary-web', 'METRICS__API_KEY': 'canary-metrics'},
                                configuration_files=[{'path': 'data/web/public/config/settings.yaml', 'content': 'title: Dashboard'}])
        self.assertEqual(result.plan.schema, 2)
        self.assertEqual(result.plan.service_names, ('web', 'metrics'))
        self.assertEqual(result.plan.components[1]['value_names'], {'API_KEY': 'METRICS__API_KEY'})
        self.assertEqual(result.plan.private_bindings['WEB__API_KEY'], {'folder': '/web', 'key': 'API_KEY'})
        self.assertEqual(result.plan.components[1]['private_bindings']['API_KEY'], {'folder': '/metrics', 'key': 'API_KEY'})
        self.assertEqual(result.sensitive['WEB__API_KEY'], 'canary-web')
        for text in (repr(result), repr(result.plan), json.dumps(result.plan.to_public_dict()),
                     json.dumps(result.plan.deployment_payload())):
            self.assertNotIn('canary-', text)
        self.assertNotIn('title: Dashboard', json.dumps(result.plan.to_public_dict()))
        self.assertIn('title: Dashboard', json.dumps(result.plan.deployment_payload()))
        self.assertEqual(result.plan.service_name, 'web')
        self.assertEqual(result.plan.images['metrics'], 'example/metrics:latest')

    def test_compose_resources_append_preserves_existing_bytes_and_is_idempotent(self):
        source = self.COMPOSE.replace('      API_KEY: ${API_KEY:?required}\n', '      PORT: 8080\n')
        result = analyze_inputs(source)
        existing = ('# Stack header\r\nname: original\r\nservices:\r\n    old:\r\n'
                    '        image: example/old # keep\r\nnetworks:\r\n    default:\r\n'
                    '        name: keep-me # comment\r\nvolumes:\r\n    old-data: # keep\r\n')
        rendered = result.plan.render_compose(existing)
        self.assertIn('        image: example/old # keep\r\n', rendered)
        self.assertIn('        name: keep-me # comment\r\n', rendered)
        self.assertIn('    old-data: # keep\r\n', rendered)
        self.assertNotIn('\n', rendered.replace('\r\n', ''))
        parsed = yaml.safe_load(rendered)
        self.assertEqual(set(parsed['services']), {'old', 'web', 'metrics'})
        self.assertEqual(set(parsed['networks']), {'default', 'monitoring'})
        self.assertEqual(set(parsed['volumes']), {'old-data', 'metrics-state'})
        self.assertEqual(result.plan.render_compose(rendered), rendered)
        with self.assertRaisesRegex(PlanFailure, '^SERVICE_COMPOSE_RESOURCE_CONFLICT$'):
            result.plan.render_compose('services:\n  old:\n    image: old\nnetworks:\n  monitoring:\n    external: true\n')

    def test_top_level_configs_and_public_file_privacy(self):
        compose = ('services:\n  demo:\n    image: example/demo\n'
                   '    configs: [settings]\n    environment:\n      TOKEN: ${TOKEN}\n'
                   'configs:\n  settings:\n    file: ./data/demo/public/settings.yaml\n')
        kwargs = dict(private_names=['TOKEN'], private_values={'TOKEN': 'canary-private'})
        result = analyze_inputs(compose, configuration_files=[{'path': 'data/demo/public/settings.yaml', 'content': 'public'}], **kwargs)
        self.assertEqual(result.plan.resources[0]['role'], 'config')
        existing = 'services:\n  old:\n    image: old\n'
        rendered = result.plan.render_compose(existing)
        self.assertEqual(yaml.safe_load(rendered)['configs']['settings']['file'], './data/demo/public/settings.yaml')
        with self.assertRaisesRegex(PlanFailure, '^SERVICE_PRIVATE_VALUE_OUTSIDE_ENV$'):
            analyze_inputs(compose, configuration_files=[{'path': 'data/demo/public/settings.yaml', 'content': 'token: canary-private'}], **kwargs)

    def test_global_names_handle_normalized_service_collisions(self):
        compose = ('services:\n  foo-bar:\n    image: example/demo\n    environment: {API_KEY: public}\n'
                   '  foo_bar:\n    image: example/demo\n    environment: {API_KEY: public}\n')
        rows = inspect_inputs(compose)
        self.assertEqual(len({row.name for row in rows}), 2)
        self.assertTrue(all(row.name.startswith('FOO_BAR__') for row in rows))

    def test_resource_merge_into_empty_mappings_and_version_header(self):
        plan = analyze_inputs('version: "3.8"\nservices:\n  demo:\n    image: example/demo\n'
                              '    volumes: [cache:/cache]\nnetworks:\n  demo-net: {}\n').plan
        for existing in ('services: {} # retained\nvolumes: {}\nnetworks: {}\n',
                         'services:\n  old:\n    image: old\nvolumes:\nnetworks:\n'):
            with self.subTest(existing=existing):
                rendered = plan.render_compose(existing)
                self.assertIn('demo', yaml.safe_load(rendered)['services'])
                self.assertIn('cache', yaml.safe_load(rendered)['volumes'])
                self.assertIn('demo-net', yaml.safe_load(rendered)['networks'])
                self.assertEqual(plan.render_compose(rendered), rendered)

    def test_top_level_literal_dollar_is_preserved_for_compose(self):
        compose = ('services:\n  demo:\n    image: example/demo\n    configs: [settings]\n'
                   'configs:\n  settings:\n    content: "hello $$HOME"\n')
        result = analyze_inputs(compose)
        self.assertEqual(result.plan.compose_resources['configs']['settings']['content'], 'hello $$HOME')

    def test_escaped_private_values_cannot_leak_in_public_configuration(self):
        compose = 'demo:\n  image: example/demo\n  volumes: [./data/demo/public:/config:ro]\n'
        with self.assertRaisesRegex(PlanFailure, '^SERVICE_PRIVATE_VALUE_OUTSIDE_ENV$'):
            analyze_inputs(compose, 'API_KEY=canary\\abc\n', private_names=['API_KEY'],
                           configuration_files=[{'path': 'data/demo/public/settings.yaml', 'content': 'key: canary\\abc'}])

    def test_schema_one_compatibility(self):
        plan = analyze_inputs('demo:\n  image: example/demo\n').plan
        self.assertEqual(plan.schema, 1)
        self.assertNotIn('components', plan.to_public_dict())
        self.assertNotIn('resources', plan.deployment_payload())


if __name__ == '__main__':
    unittest.main()
