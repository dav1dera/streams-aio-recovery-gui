/* Real browser checks using only a synthetic bridge; never contacts a VM. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

async function main() {
  const [html, fixturePath, output, chrome] = process.argv.slice(2);
  assert(html && fixturePath && output, 'Supply document, safe fixture and output directory');
  fs.mkdirSync(output, {recursive: true});
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  fixture.bundleResources = [
    {id: 'data', service: 'demo', type: 'volume', source: 'demo_data', target: '/app/data', read_only: false, role: 'data', recovery: {method: 'stopped_archive'}},
    {id: 'cache', service: 'demo', type: 'volume', source: 'demo_cache', target: '/app/cache', read_only: false, role: 'data', recovery: {method: 'stopped_archive'}},
    {id: 'config', service: 'demo', type: 'bind', source: './data/demo/public/settings.yaml', target: '/app/settings.yaml', read_only: true, role: 'config', recovery: {method: 'recreate'}},
    {id: 'external', service: 'demo', type: 'volume', source: 'existing_data', target: '/app/external', read_only: false, role: 'external', recovery: {method: 'external'}},
    {id: 'socket', service: 'socket-proxy', type: 'bind', source: '/var/run/docker.sock', target: '/var/run/docker.sock', read_only: true, role: 'runtime', recovery: {method: 'recreate'}}
  ];
  fixture.bundlePlan = {
    schema: 2, service_name: 'demo', service_names: ['demo', 'socket-proxy'], images: {demo: 'example/demo:latest', 'socket-proxy': 'example/socket-proxy:latest'},
    components: [{service_name: 'demo', image: 'example/demo:latest', public_env_path: 'data/demo/.env', private_env_path: '.secrets/demo.env', private_bindings: {PASSWORD: {folder: '/demo', key: 'PASSWORD', value: 'BINDING_VALUE_CANARY'}}, public_env_text: 'COMPONENT_VALUE_CANARY'}, {service_name: 'socket-proxy', image: 'example/socket-proxy:latest', public_env_path: 'data/socket-proxy/.env'}],
    configuration_files: [{path: 'data/demo/public/settings.yaml', mode: 416, sha256: 'a'.repeat(64), content: 'CONFIG_CONTENT_CANARY'}],
    resources: fixture.bundleResources,
    compose_fragment: 'COMPOSE_CONTENT_CANARY', public_env_text: 'ENV_VALUE_CANARY', private_values: {PASSWORD: 'PRIVATE_VALUE_CANARY'}
  };
  // Fulfill only the three bundled assets locally; no browser network access is needed.
  const entryUrl = 'http://127.0.0.1/';
  const assets = new Map([['/', ['index.html', 'text/html']], ['/app.js', ['app.js', 'text/javascript']], ['/app.css', ['app.css', 'text/css']]]);
  const restrictNetwork = route => {
    const url = new URL(route.request().url()), asset = assets.get(url.pathname);
    if (url.origin !== new URL(entryUrl).origin) return route.abort();
    if (!asset) return route.fulfill({status: 404, body: ''});
    return route.fulfill({status: 200, contentType: asset[1] + '; charset=utf-8', body: fs.readFileSync(path.join(path.dirname(path.resolve(html)), asset[0]))});
  };
  let browser;
  try {
    browser = await chromium.launch({headless: true, ...(chrome ? {executablePath: chrome} : {})});
    const page = await browser.newPage({viewport: {width: 1360, height: 930}, reducedMotion: 'reduce'});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route(/^https?:/, restrictNetwork);
    await page.addInitScript(value => {
      const events = [], calls = [];
      let busy = false;
      function job(operation, rows) {
        busy = true;
        events.push(...rows, {kind: 'done', operation, success: rows.every(row => row.kind !== 'error')});
        return {ok: true, job_id: 'a'.repeat(32)};
      }
      window.__testCalls = calls;
      window.__testImportCancel = true;
      window.__testSettingUpdates = 0;
      window.__testEvents = rows => events.push(...rows);
      window.pywebview = {api: {
        initialize: async () => value.initial,
        update_settings: async () => {window.__testSettingUpdates += 1; return {ok: true};},
        invalidate_service: async () => ({ok: true}),
        import_service_bundle: async () => ({ok: true, bundle: window.__testImportCancel ? null : {compose: value.compose, env: value.env, service_name: '', configuration_files: [{path: 'data/demo/public/settings.yaml', content: 'title: CONFIG_CONTENT_CANARY\n', mode: 416}], storage_policies: [{service: 'demo', target: '/app/external', method: 'external'}], private_values: {PASSWORD: 'IMPORTED_PRIVATE_VALUE_CANARY'}, reviewed: true, receipt: 'IMPORTED_RECEIPT_CANARY'}}),
        poll: async () => {const rows = events.splice(0); if (rows.some(row => row.kind === 'done')) busy = false; return {ok: true, busy, events: rows};},
        load_backups: async () => job('load_backups', [{kind: 'choices', tags: [value.point.tag]}, {kind: 'point', ...value.point}]),
        load_backup: async () => job('load_backup', [{kind: 'point', ...value.point}]),
        prepare_lab: async input => {
          calls.push('prepare_lab');
          window.__testLabPaste = input.age_identity_mode === 'paste' && input.age_identity === '' && input.age_identity_text === 'AGE-SECRET-KEY-1SYNTHETICNOTAPRIVATEKEY1234';
          return job('prepare_lab', [{kind: 'error', code: 'SSH_AUTH_FAILED', target_role: 'infisical', description: 'Credenziali SSH da verificare.'}]);
        },
        recover: async () => {calls.push('recover'); busy = true; return {ok: true, job_id: 'b'.repeat(32)};},
        analyze_service: async input => {window.__testAnalyzePayload = input; return {ok: true, variables: value.variables, resources: value.bundleResources};},
        prepare_service: async input => {
          window.__testPreparePayload = input;
          const plan = JSON.parse(JSON.stringify(value.bundlePlan));
          plan.resources.forEach(resource => {
            const policy = (input.storage_policies || []).find(item => item.service === resource.service && item.target === resource.target);
            if (policy) resource.recovery.method = policy.method;
          });
          return {ok: true, plan};
        },
        inspect_service: async () => {
          if (window.__testInspectError) { const failure = window.__testInspectError; window.__testInspectError = null; return job('inspect_service', [{kind: 'error', ...failure}]); }
          return job('inspect_service', [{kind: 'inspected', verification_scope: 'local_lab', resume: window.__testResume === true, resume_phase: window.__testResume ? 'SERVICE_READY' : ''}]);
        },
        update_service_tools: async () => { calls.push('update_service_tools'); return job('update_service_tools', [{kind: 'tools_prepared'}]); },
        apply_service: async () => {calls.push('apply_service'); return job('apply_service', [{kind: 'completed', operation: 'service', status: 'PASS_LOCAL', checks: {service: true, agent: true, github: false, backup: false}}]);},
        cancel: async () => ({ok: true}),
        answer_host_key: async () => ({ok: true}),
        choose_file: async () => ({ok: true, path: ''}),
        save_report: async () => ({ok: true, path: ''}),
        save_plan: async () => ({ok: true, path: ''}),
        open_guide: async () => ({ok: true})
      }};
    }, fixture);
    await page.goto(entryUrl);
    await page.waitForFunction(() => window.recoveryUI && window.recoveryUI.ready && document.body.dataset.bridgeState === 'connected');
    await page.screenshot({path: path.join(output, '01-panoramica.png')});
    await page.locator('[data-page="connections"]').click();
    await page.locator('[data-setting="host"]').fill('192.0.2.30');
    await page.locator('[data-setting="infisical_host"]').fill('192.0.2.33');
    const syntheticIdentity = 'AGE-SECRET-KEY-1SYNTHETICNOTAPRIVATEKEY1234';
    await page.locator('[data-age-mode="paste"]').click();
    await page.locator('#age-identity-text').fill(syntheticIdentity);
    assert.equal(await page.locator('#age-identity-text').getAttribute('type'), 'password');
    assert.equal(await page.locator('#age-identity-text').getAttribute('autocomplete'), 'off');
    assert(await page.locator('#age-file-panel').isHidden());
    await page.locator('#age-paste-panel .toggle-password').click();
    assert.equal(await page.locator('#age-identity-text').getAttribute('type'), 'text');
    await page.locator('[data-age-mode="file"]').click();
    assert.equal(await page.locator('#age-identity-text').inputValue(), '', 'Leaving paste mode must clear the pasted identity');
    assert.equal(await page.locator('#age-identity-text').getAttribute('type'), 'password', 'Returning to paste mode must restore masking');
    await page.locator('[data-age-mode="paste"]').click();
    await page.locator('#age-identity-text').fill(syntheticIdentity);
    assert.equal(await page.evaluate(() => window.__testSettingUpdates), 0, 'Typing and selecting age mode must not call the native bridge');
    assert(!(await page.locator('body').textContent()).includes(syntheticIdentity), 'The identity must not appear in summaries or messages');
    await page.locator('#load-backups').click();
    await page.waitForFunction(tag => document.querySelector('#backup-tag').value === tag, fixture.point.tag);
    await page.screenshot({path: path.join(output, '02-accessi.png')});
    await page.locator('#save-settings').click();
    await page.locator('[data-page="overview"]').click();
    await page.locator('#recover-resume').click();
    await page.evaluate(() => window.__testEvents([{kind: 'stage', stage: 'INFISICAL_TRANSFER', status: 'PASS'}]));
    await page.waitForFunction(() => document.querySelector('#recovery-phases .phase-tile').classList.contains('running'));
    assert(!(await page.locator('#recovery-phases .phase-tile').first().getAttribute('class')).includes('pass'), 'An intermediate PASS must not complete an entire phase');
    await page.evaluate(() => window.__testEvents([
      {kind: 'stage', stage: 'INFISICAL_SERVER', status: 'PASS'},
      {kind: 'resumed_selection', point: {tag: 'dr-20261019T120000Z', public_commit: 'b'.repeat(40), aio_snapshot: true}, routing_mode: 'production_recovery', domain_target_address: '192.0.2.42'},
      {kind: 'done', operation: 'recover', success: true}
    ]));
    await page.waitForFunction(() => document.querySelector('#recovery-phases .phase-tile').classList.contains('pass'));
    assert.equal(await page.locator('#backup-tag').inputValue(), 'dr-20261019T120000Z', 'Resume must show the backup actually selected by the backend');
    assert.equal(await page.locator('#backup-commit').inputValue(), 'b'.repeat(40));
    assert.equal(await page.locator('[data-setting="domain_target_address"]').inputValue(), '192.0.2.42');
    assert.equal(await page.locator('[data-setting="routing_mode"]').inputValue(), 'production_recovery');
    await page.locator('[data-page="service"]').click();
    await page.locator('input[name="verification-scope"][value="local_lab"]').check();
    await page.locator('#prepare-lab').click();
    await page.waitForFunction(() => !document.querySelector('#lab-feedback').hidden && document.querySelector('#lab-feedback').textContent.includes('SSH_AUTH_FAILED'));
    assert.equal(await page.evaluate(() => window.__testLabPaste), true, 'The explicit lab action must receive the in-memory identity without a file');
    assert(await page.locator('#global-status-detail').isVisible(), 'Error detail must remain visible without scrolling');
    assert((await page.locator('#global-status-detail').textContent()).includes('VM Infisical:'), 'The failed VM must be identified in the persistent error');
    assert((await page.locator('#lab-feedback').textContent()).includes('VM Infisical:'), 'The failed VM must be identified in lab feedback');
    await page.evaluate(() => window.__testEvents([{kind: 'error', code: 'SSH_AUTH_FAILED', target_role: 'stack', description: 'Credenziali SSH da verificare.'}]));
    await page.waitForFunction(() => document.querySelector('#global-status-detail').textContent.includes('VM stack:'));
    assert((await page.locator('#lab-feedback').textContent()).includes('VM stack:'));
    await page.evaluate(() => window.__testEvents([{kind: 'error', code: 'SSH_AUTH_FAILED', target_role: 'PRIVATE_ROLE_CANARY', description: 'Credenziali SSH da verificare.'}]));
    await page.waitForFunction(() => document.querySelector('#global-status-detail').textContent === 'Credenziali SSH da verificare.');
    assert(!(await page.locator('body').textContent()).includes('PRIVATE_ROLE_CANARY'), 'Unknown target-role data must never be rendered');
    await page.screenshot({path: path.join(output, '03-esito-laboratorio.png')});
    await page.locator('#service-next').click();
    await page.locator('#service-compose').fill(fixture.compose);
    await page.locator('#service-env').fill(fixture.env);
    await page.locator('#import-service-bundle').click();
    assert.equal(await page.locator('#service-compose').inputValue(), fixture.compose, 'Cancelling import preserves the draft');
    assert.equal(await page.locator('.configuration-file').count(), 0);
    await page.evaluate(() => {window.__testImportCancel = false;});
    await page.locator('#import-service-bundle').click();
    assert.equal(await page.locator('#service-env').inputValue(), fixture.env);
    assert.equal(await page.locator('[data-configuration-field="path"]').inputValue(), 'data/demo/public/settings.yaml');
    assert.equal(await page.locator('[data-configuration-field="mode"]').inputValue(), '0640');
    assert.equal(await page.locator('#service-reviewed').isChecked(), false, 'Import cannot mark a draft as reviewed');
    await page.locator('#configuration-editor summary').click();
    await page.locator('#add-configuration-file').click();
    await page.locator('.configuration-file').last().locator('[data-configuration-field="path"]').fill('REMOVED_FILE_CANARY');
    await page.locator('.remove-configuration-file').last().click();
    assert.equal(await page.locator('.configuration-file').count(), 1, 'Removing a file must remove its draft entry');
    await page.screenshot({path: path.join(output, '04-servizio.png')});
    await page.locator('#service-next').click();
    await page.waitForFunction(() => !document.querySelector('#service-step-2').hidden);
    assert.deepEqual(await page.evaluate(() => window.__testAnalyzePayload.configuration_files), [{path: 'data/demo/public/settings.yaml', content: 'title: CONFIG_CONTENT_CANARY\n', mode: 416}]);
    assert.equal(await page.locator('#service-resource-rows select').count(), 0, 'Recovery methods are fixed by the reviewed inventory');
    assert.equal(await page.locator('#service-resource-rows').getByText('Archivia con container fermi', {exact: true}).count(), 2);
    assert.equal(await page.locator('#service-resource-rows').getByText('Ricreato durante il recupero', {exact: true}).count(), 2);
    assert.equal(await page.locator('#service-resource-rows').getByText('Risorsa esterna: da predisporre sulla destinazione', {exact: true}).count(), 1);
    await page.screenshot({path: path.join(output, '04b-dati-e-segreti.png')});
    await page.locator('#service-reviewed').check();
    await page.locator('#service-next').click();
    await page.waitForFunction(() => !document.querySelector('#service-step-3').hidden);
    assert.deepEqual(await page.evaluate(() => window.__testPreparePayload.storage_policies), [
      {service: 'demo', target: '/app/external', method: 'external'},
      {service: 'demo', target: '/app/data', method: 'stopped_archive'},
      {service: 'demo', target: '/app/cache', method: 'stopped_archive'}
    ]);
    assert.deepEqual(await page.evaluate(() => window.__testPreparePayload.configuration_files), [{path: 'data/demo/public/settings.yaml', content: 'title: CONFIG_CONTENT_CANARY\n', mode: 416}]);
    assert.deepEqual(await page.evaluate(() => window.__testPreparePayload.private_values), {}, 'Import ignores private values');
    assert.deepEqual(await page.evaluate(() => window.__testAnalyzePayload.storage_policies), [{service: 'demo', target: '/app/external', method: 'external'}]);
    assert.equal(await page.locator('#plan-components .plan-component').count(), 2);
    assert.equal(await page.locator('#plan-files .plan-file').count(), 4, 'Only components with private bindings list a private file');
    assert((await page.locator('#plan-service-name').textContent()).includes('demo + socket-proxy'));
    assert((await page.locator('#plan-files').textContent()).includes('0640'));
    assert((await page.locator('#plan-resource-rows').textContent()).includes('Risorsa esterna: da predisporre sulla destinazione'));
    assert((await page.locator('#plan-resource-rows').textContent()).includes('Archivia con container fermi'));
    for (const canary of ['CONFIG_CONTENT_CANARY', 'COMPONENT_VALUE_CANARY', 'COMPOSE_CONTENT_CANARY', 'ENV_VALUE_CANARY', 'PRIVATE_VALUE_CANARY', 'BINDING_VALUE_CANARY', 'IMPORTED_PRIVATE_VALUE_CANARY', 'IMPORTED_RECEIPT_CANARY', 'REMOVED_FILE_CANARY']) {
      assert(!(await page.locator('#service-step-3').textContent()).includes(canary), 'The recap must contain metadata only: ' + canary);
    }
    await page.screenshot({path: path.join(output, '04c-piano-completo.png')});
    await page.setViewportSize({width: 980, height: 740});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'Service recap must fit the compact window');
    await page.setViewportSize({width: 1360, height: 930});
    await page.evaluate(() => { window.__testInspectError = {
      code: 'ONBOARDING_PUBLIC_PREFLIGHT_FAILED', description: 'UNAPPROVED_TRANSPORT_DESCRIPTION',
      diagnostic: {schema: 1, stage: 'GITHUB', code: 'PRIVATE_VALUE_IN_PUBLIC_FILE', path: 'data/demo/public/settings.yaml', lines: [1, 3], references: ['/demo/PASSWORD'], retryable: true}
    }; });
    await page.locator('#inspect-service').click();
    await page.waitForFunction(() => document.querySelector('#service-feedback').textContent.includes('Righe: 1, 3') && !document.querySelector('#inspect-service').disabled);
    assert((await page.locator('#service-feedback').textContent()).includes('data/demo/public/settings.yaml'));
    assert(!(await page.locator('body').textContent()).includes('UNAPPROVED_TRANSPORT_DESCRIPTION'), 'Fixed diagnostic text must replace unapproved transport prose');
    assert(await page.locator('#apply-service').isDisabled(), 'A diagnostic failure never unlocks apply');
    await page.evaluate(() => { window.__testInspectError = {
      code: 'ONBOARDING_RESOURCE_BACKUP_CAPABILITY_REQUIRED'
    }; });
    await page.locator('#inspect-service').click();
    await page.waitForFunction(() => document.querySelector('#prepare-service-tools') && !document.querySelector('#prepare-service-tools').disabled);
    assert(!(await page.evaluate(() => window.__testCalls)).includes('update_service_tools'), 'Legacy backup capability preparation also requires an explicit click');
    await page.evaluate(() => { window.__testInspectError = {
      code: 'ONBOARDING_TOOLING_UPDATE_REQUIRED',
      diagnostic: {schema: 1, stage: 'HOST', code: 'TOOLING_UPDATE_REQUIRED', retryable: true}
    }; });
    await page.locator('#inspect-service').click();
    await page.waitForFunction(() => document.querySelector('#prepare-service-tools') && !document.querySelector('#prepare-service-tools').disabled);
    assert(!(await page.evaluate(() => window.__testCalls)).includes('update_service_tools'), 'Preparation requires its own explicit click');
    await page.locator('#prepare-service-tools').click();
    await page.waitForFunction(() => document.querySelector('#service-feedback').textContent.includes('Strumenti VM preparati') && !document.querySelector('#inspect-service').disabled);
    assert(await page.locator('#apply-service').isDisabled(), 'Preparing tooling requires a fresh VM check');
    await page.evaluate(() => { window.__testResume = true; });
    await page.locator('#inspect-service').click();
    await page.waitForFunction(() => !document.querySelector('#apply-service').disabled);
    assert((await page.locator('#apply-service').textContent()).includes('Riprendi verifiche'));
    assert((await page.locator('#service-feedback').textContent()).includes('già presente'));
    await page.screenshot({path: path.join(output, '04d-ripresa-verifiche.png')});
    await page.locator('#apply-service').click();
    await page.waitForFunction(() => document.querySelector('#statusbar').classList.contains('success') && document.querySelector('#global-status-title').textContent.toLowerCase().includes('collaudo'));
    assert(await page.locator('#global-status-detail').textContent().then(text => /GitHub|backup/i.test(text)), 'Local completion must disclose publication exclusions');
    await page.screenshot({path: path.join(output, '05-verifica-locale.png')});
    assert.deepEqual(errors, [], 'No browser exception may hide a clicked action');
    assert(!(await page.locator('body').textContent()).includes(syntheticIdentity), 'The identity must not appear in status or diagnostics');
    assert.deepEqual(await page.evaluate(() => window.__testCalls), ['recover', 'prepare_lab', 'update_service_tools', 'apply_service']);
    await page.setViewportSize({width: 980, height: 740});
    await page.locator('[data-page="connections"]').click();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'No horizontal document overflow at minimum window size');
    await page.screenshot({path: path.join(output, '06-finestra-compatta.png')});
    const lateContext = await browser.newContext({viewport: {width: 980, height: 740}});
    const latePage = await lateContext.newPage();
    await latePage.route(/^https?:/, restrictNetwork);
    await latePage.goto(entryUrl);
    await latePage.waitForFunction(() => window.recoveryUI && window.recoveryUI.ready);
    assert.equal(await latePage.locator('body').getAttribute('data-bridge-state'), 'preview');
    await latePage.evaluate(initial => {
      window.pywebview = {api: {
        initialize: async () => {window.__lateInitialized = true; return initial;},
        poll: async () => ({ok: true, busy: false, events: []}),
        analyze_service: async input => {window.__lateAnalyze = input; return {ok: true, variables: [], resources: []};},
        prepare_service: async input => {window.__latePrepare = input; return {ok: true, plan: {schema: 1, service_name: 'simple', image: 'example/simple:latest', public_env_path: 'data/simple/.env'}};}
      }};
      // The native host emits this event on window after document loading.
      // It does not bubble to document; file previews cannot exercise this.
      window.dispatchEvent(new CustomEvent('pywebviewready'));
    }, fixture.initial);
    await latePage.waitForFunction(() => document.body.dataset.bridgeState === 'connected');
    assert.equal(await latePage.evaluate(() => window.__lateInitialized), true);
    await latePage.locator('[data-page="service"]').click();
    await latePage.locator('#service-next').click();
    await latePage.locator('#service-compose').fill('services:\n  simple:\n    image: example/simple:latest\n');
    await latePage.locator('#service-next').click();
    await latePage.waitForFunction(() => !document.querySelector('#service-step-2').hidden);
    assert(await latePage.locator('#service-resources').isHidden(), 'An empty inventory does not add noise to simple services');
    await latePage.locator('#service-reviewed').check();
    await latePage.locator('#service-next').click();
    await latePage.waitForFunction(() => !document.querySelector('#service-step-3').hidden);
    const simpleDraft = await latePage.evaluate(() => window.__latePrepare);
    assert(!Object.hasOwn(simpleDraft, 'configuration_files'), 'Absent configuration files must not add a payload field');
    assert(!Object.hasOwn(simpleDraft, 'storage_policies'), 'Absent data policies must not add a payload field');
    assert.equal(await latePage.locator('#plan-service-name').textContent(), 'simple', 'Single-service plans remain supported');
    assert.equal(await latePage.locator('#plan-image').textContent(), 'example/simple:latest');
    await lateContext.close();
    process.stdout.write('WEB_UI_BROWSER PASS\n');
  } finally {
    if (browser) await browser.close();
  }
}
main().catch(error => {process.stderr.write(String(error.stack || error) + '\n'); process.exitCode = 1;});
