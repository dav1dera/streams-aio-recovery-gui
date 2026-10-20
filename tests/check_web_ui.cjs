/* Real browser checks using only a synthetic bridge; never contacts a VM. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {pathToFileURL} = require('node:url');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

async function main() {
  const [html, fixturePath, output, chrome] = process.argv.slice(2);
  assert(html && fixturePath && output, 'Supply document, safe fixture and output directory');
  fs.mkdirSync(output, {recursive: true});
  const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
  const browser = await chromium.launch({headless: true, ...(chrome ? {executablePath: chrome} : {})});
  try {
    const page = await browser.newPage({viewport: {width: 1360, height: 930}, reducedMotion: 'reduce'});
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route(/^https?:/, route => route.abort());
    await page.addInitScript(value => {
      const events = [], calls = [];
      let busy = false;
      function job(operation, rows) {
        busy = true;
        events.push(...rows, {kind: 'done', operation, success: rows.every(row => row.kind !== 'error')});
        return {ok: true, job_id: 'a'.repeat(32)};
      }
      window.__testCalls = calls;
      window.__testEvents = rows => events.push(...rows);
      window.pywebview = {api: {
        initialize: async () => value.initial,
        update_settings: async () => ({ok: true}),
        invalidate_service: async () => ({ok: true}),
        poll: async () => {const rows = events.splice(0); if (rows.some(row => row.kind === 'done')) busy = false; return {ok: true, busy, events: rows};},
        load_backups: async () => job('load_backups', [{kind: 'choices', tags: [value.point.tag]}, {kind: 'point', ...value.point}]),
        load_backup: async () => job('load_backup', [{kind: 'point', ...value.point}]),
        prepare_lab: async () => {calls.push('prepare_lab'); return job('prepare_lab', [{kind: 'error', code: 'SSH_AUTH_FAILED', description: 'Credenziali SSH da verificare.'}]);},
        recover: async () => {calls.push('recover'); busy = true; return {ok: true, job_id: 'b'.repeat(32)};},
        analyze_service: async () => ({ok: true, variables: value.variables}),
        prepare_service: async () => ({ok: true, plan: value.plan}),
        inspect_service: async () => job('inspect_service', [{kind: 'inspected', verification_scope: 'local_lab'}]),
        apply_service: async () => {calls.push('apply_service'); return job('apply_service', [{kind: 'completed', operation: 'service', status: 'PASS_LOCAL', checks: {service: true, agent: true, github: false, backup: false}}]);},
        cancel: async () => ({ok: true}),
        answer_host_key: async () => ({ok: true}),
        choose_file: async () => ({ok: true, path: ''}),
        save_report: async () => ({ok: true, path: ''}),
        save_plan: async () => ({ok: true, path: ''}),
        open_guide: async () => ({ok: true})
      }};
    }, fixture);
    await page.goto(pathToFileURL(path.resolve(html)).href);
    await page.waitForFunction(() => window.recoveryUI && window.recoveryUI.ready);
    await page.screenshot({path: path.join(output, '01-panoramica.png')});
    await page.locator('[data-page="connections"]').click();
    await page.locator('[data-setting="host"]').fill('192.0.2.30');
    await page.locator('[data-setting="infisical_host"]').fill('192.0.2.33');
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
    assert(await page.locator('#global-status-detail').isVisible(), 'Error detail must remain visible without scrolling');
    await page.screenshot({path: path.join(output, '03-esito-laboratorio.png')});
    await page.locator('#service-next').click();
    await page.locator('#service-compose').fill(fixture.compose);
    await page.locator('#service-env').fill(fixture.env);
    await page.screenshot({path: path.join(output, '04-servizio.png')});
    await page.locator('#service-next').click();
    await page.waitForFunction(() => !document.querySelector('#service-step-2').hidden);
    await page.locator('#service-reviewed').check();
    await page.locator('#service-next').click();
    await page.waitForFunction(() => !document.querySelector('#service-step-3').hidden);
    await page.locator('#inspect-service').click();
    await page.waitForFunction(() => !document.querySelector('#apply-service').disabled);
    await page.locator('#apply-service').click();
    await page.waitForFunction(() => document.querySelector('#statusbar').classList.contains('success') && document.querySelector('#global-status-title').textContent.toLowerCase().includes('collaudo'));
    assert(await page.locator('#global-status-detail').textContent().then(text => /GitHub|backup/i.test(text)), 'Local completion must disclose publication exclusions');
    await page.screenshot({path: path.join(output, '05-verifica-locale.png')});
    assert.deepEqual(errors, [], 'No browser exception may hide a clicked action');
    assert.deepEqual(await page.evaluate(() => window.__testCalls), ['recover', 'prepare_lab', 'apply_service']);
    await page.setViewportSize({width: 980, height: 740});
    await page.locator('[data-page="connections"]').click();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'No horizontal document overflow at minimum window size');
    await page.screenshot({path: path.join(output, '06-finestra-compatta.png')});
    process.stdout.write('WEB_UI_BROWSER PASS\n');
  } finally {
    await browser.close();
  }
}
main().catch(error => {process.stderr.write(String(error.stack || error) + '\n'); process.exitCode = 1;});
