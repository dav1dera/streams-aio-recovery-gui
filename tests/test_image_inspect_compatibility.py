"""Docker image template regression, including the typed/raw fallback boundary.

The CLI first evaluates Go fields on image.InspectResponse, then retries raw
JSON with missingkey=error when a field is unavailable. ID has JSON name Id;
Config.User is a typed string whose empty value is omitted from API JSON.

This fixture models those documented semantics for the field-only json actions
used here. It does not execute Go templates, a Docker daemon, or a live VM.
The complete first-boot checker and its image-account checks run unchanged.
"""
import copy
import importlib.util
import json
from pathlib import Path
import re
from types import SimpleNamespace as N
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    'image_inspect_runtime_fixtures', ROOT/'tests/test_runtime_profile.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
profile = fixtures.profile


class TemplateFieldError(ValueError):
    pass


class TypedAndRawInspector:
    """Simulate the CLI's two template attempts, with no pre-rendered result."""
    action = re.compile(r'\{\{json (\.[A-Za-z][A-Za-z0-9_.]*)\}\}')

    def __init__(self, metadata):
        self.typed = N(ID=metadata['Id'], Os=metadata['Os'],
                       Architecture=metadata['Architecture'],
                       Config=N(Env=metadata['Env'], User=metadata['User']))
        # Config.User uses omitempty in the image API's config serialization.
        config = {'Env': copy.deepcopy(metadata['Env'])}
        if metadata['User']:
            config['User'] = metadata['User']
        self.raw = dict(Id=metadata['Id'], Os=metadata['Os'],
                        Architecture=metadata['Architecture'], Config=config)
        self.attempts = []

    def evaluate(self, template, value):
        def action(match):
            item = value
            for field in match[1][1:].split('.'):
                try:
                    item = item[field] if isinstance(item, dict) else getattr(item, field)
                except (KeyError, AttributeError):
                    raise TemplateFieldError('TEMPLATE_FIELD_MISSING') from None
            return json.dumps(item, separators=(',', ':'))
        return self.action.sub(action, template).encode()

    def render(self, template):
        self.attempts.append('typed')
        try:
            return self.evaluate(template, self.typed)
        except TemplateFieldError:
            self.attempts.append('raw')
            return self.evaluate(template, self.raw)


class ImageInspectCompatibility(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.FirstBootChecks(methodName='runTest')
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.inspectors = []

    def docker_run(self, args):
        if args[:3] != ['docker', 'image', 'inspect']:
            return self.fixture.docker_run(args)
        self.assertEqual(args[3], '--format')
        self.fixture.commands.append(args)
        inspector = TypedAndRawInspector(self.fixture.images[args[-1]])
        self.inspectors.append(inspector)
        return inspector.render(args[4])

    def check(self):
        return profile.readonly_first_boot_checks(
            self.fixture.root, self.fixture.model, self.docker_run)

    def test_former_id_spelling_fails_on_omitted_empty_user(self):
        inspector = TypedAndRawInspector(self.fixture.images[profile.PG_IMAGE])
        self.assertNotIn('User', inspector.raw['Config'])
        old_template = profile.IMAGE_METADATA_FORMAT.replace('.ID', '.Id')
        with self.assertRaisesRegex(TemplateFieldError, '^TEMPLATE_FIELD_MISSING$'):
            inspector.render(old_template)
        self.assertEqual(inspector.attempts, ['typed', 'raw'])

    def test_typed_id_keeps_empty_user_and_all_four_image_checks_pass(self):
        expected = {'pgdata': 'streams-aio_pgdata',
                    'postgres-cluster': 'streams-aio_postgres-cluster'}
        self.assertEqual(self.check(), expected)
        self.assertEqual(len(self.inspectors), 4)
        self.assertTrue(all(item.attempts == ['typed'] for item in self.inspectors))
        postgres = json.loads(self.inspectors[0].render(profile.IMAGE_METADATA_FORMAT))
        self.assertEqual(postgres['User'], '')
        self.assertEqual(postgres['Id'], self.fixture.images[profile.PG_IMAGE]['Id'])
        for reference in profile.FIRST_BOOT_IMAGES:
            self.assertIn(['docker', 'image', 'save', reference], self.fixture.commands)

    def test_explicit_image_users_are_preserved_without_raw_fallback(self):
        for reference in profile.FIRST_BOOT_IMAGES[1:]:
            with self.subTest(reference=reference):
                metadata = self.fixture.images[reference]
                inspector = TypedAndRawInspector(metadata)
                actual = json.loads(inspector.render(profile.IMAGE_METADATA_FORMAT))
                self.assertEqual(actual['User'], metadata['User'])
                self.assertEqual(inspector.attempts, ['typed'])

    def test_wrong_platform_major_and_id_are_still_refused(self):
        before = copy.deepcopy(self.fixture.images)
        for field, value in (('Os', 'windows'), ('Architecture', 'arm64'),
                             ('Env', ['PG_MAJOR=17']), ('Id', 'invalid')):
            with self.subTest(field=field):
                self.fixture.images = copy.deepcopy(before)
                self.fixture.images[profile.PG_IMAGE][field] = value
                with self.assertRaisesRegex(profile.Refused, '^RUNTIME_PROFILE_IMAGE_CHANGED$'):
                    self.check()


if __name__ == '__main__':
    unittest.main()
