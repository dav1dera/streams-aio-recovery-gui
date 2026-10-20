/* Original offline desktop interface. Values and credentials stay in memory. */
(() => {
  'use strict';

  const $ = (selector, parent = document) => parent.querySelector(selector);
  const $$ = (selector, parent = document) => Array.from(parent.querySelectorAll(selector));
  const PAGE_TITLES = { overview: 'Panoramica', connections: 'Accessi e backup', service: 'Aggiungi servizio', advanced: 'Opzioni avanzate' };
  const STAGES = { HOST: 'VM e stack', INFISICAL: 'Segreti Infisical', FILES: 'Compose e file', AGENT: 'Collegamento Agent', SERVICE: 'Salute del servizio', GITHUB: 'Pubblicazione GitHub', BACKUP: 'Backup cifrato' };
  const PHASES = [ ['Infisical', 'INFISICAL'], ['Stack', 'FILES'], ['AIO', 'AIO'], ['Agent', 'AGENT'], ['Domini', 'DOMAINS'], ['Servizi', 'SERVICE'] ];
  const STATUS_LABELS = { pending: 'In attesa', running: 'In corso', pass: 'Verificato', failed: 'Da risolvere', skipped: 'Escluso' };
  const SOURCE_LABELS = { env: '.env', compose: 'Compose', interpolation: 'Riferimento' };
  const FILE_KINDS = new Set(['age_identity', 'ssh_key', 'infisical_key', 'supplemental_inputs']);
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const state = {
    initialized: false, page: 'overview', submitting: false, backendBusy: false, operation: null,
    settings: {}, settingsDirty: false, version: '', errors: {}, labels: {}, progressText: {}, phaseStages: {}, finishedStages: new Set(),
    point: null, stages: {}, phases: {}, phaseLabels: {}, activePhase: null, machines: {}, history: [], activeHostKey: null, hostKeys: [], pollInFlight: false,
    service: { step: 0, analyzed: false, variables: [], privateNames: new Set(), privateValues: Object.create(null),
      selectedVariable: '', plan: null, inspected: false, completed: false, rootEdited: false, scope: 'full' }
  };
  window.recoveryUI = { ready: false };

  function text(value, fallback = '') { return typeof value === 'string' ? value : fallback; }
  function element(tag, className, content) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = String(content);
    return node;
  }
  function icon(name, small = true) {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', small ? 'icon small' : 'icon');
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.append(use);
    return svg;
  }
  function api() { return window.pywebview && window.pywebview.api; }
  function busy() { return state.submitting || state.backendBusy; }
  function privateRequired() { return state.service.privateNames.size > 0; }
  function fixedError(code, description) { return { ok: false, code, description }; }
  function statusTone(status) {
    if (status === 'PASS' || status === 'VERIFIED') return 'pass';
    if (status === 'RUNNING' || status === 'START') return 'running';
    if (status === 'FAILED' || status === 'REFUSED' || status === 'ERROR') return 'failed';
    if (status === 'SKIPPED') return 'skipped';
    return 'pending';
  }
  function setGlobal(title, detail, tone = 'pending') {
    $('#global-status-title').textContent = title;
    $('#global-status-detail').textContent = detail;
    $('#global-status-dot').className = 'status-dot ' + tone;
    $('#statusbar').className = 'statusbar' + (tone === 'failed' ? ' error' : tone === 'pass' ? ' success' : '');
  }
  function feedback(id, message, tone = '') {
    const node = $('#' + id);
    node.textContent = message;
    node.className = 'inline-feedback' + (tone ? ' ' + tone : '');
    node.hidden = !message;
  }
  function showError(result) {
    const code = text(result && result.code, 'DESKTOP_OPERATION_FAILED');
    const description = text(result && result.description, state.errors[code] || 'Il controllo non è stato completato. Conserva gli esiti prima di riprovare.');
    setGlobal(code, description, 'failed');
    if (state.operation === 'lab') feedback('lab-feedback', code + '\n' + description, 'error');
    if (state.page === 'service' && state.operation !== 'lab') feedback('service-feedback', code + '\n' + description, 'error');
    if (state.operation === 'service') state.service.inspected = false;
    addActivity(code, description, 'failed');
    renderServiceActions();
  }
  async function call(method, args = [], silent = false) {
    const bridge = api();
    if (!bridge || typeof bridge[method] !== 'function') {
      const result = fixedError('DESKTOP_CONNECTION_REQUIRED', 'Apri questa interfaccia dall’app Streams AIO Recovery per usare le operazioni. In anteprima nessuna VM viene contattata.');
      if (!silent) showError(result);
      return null;
    }
    try {
      const result = await bridge[method](...args);
      if (!result || result.ok !== true) {
        if (!silent) showError(result || fixedError('DESKTOP_RESPONSE_INVALID', 'L’app non ha restituito un esito valido.'));
        return null;
      }
      return result;
    } catch (_) {
      if (!silent) showError(fixedError('DESKTOP_CONNECTION_FAILED', 'Il collegamento con l’app si è interrotto. Nessuna credenziale viene inserita negli esiti.'));
      return null;
    }
  }

  function collectSettings() {
    const result = {};
    $$('[data-setting]').forEach(input => { result[input.dataset.setting] = input.value; });
    return result;
  }
  function syncSettings(defaults) {
    $$('[data-setting]').forEach(input => {
      if (Object.prototype.hasOwnProperty.call(defaults, input.dataset.setting)) input.value = text(defaults[input.dataset.setting]);
    });
    state.settings = collectSettings();
    state.settingsDirty = false;
    refreshSummaries();
  }
  async function flushSettings(values = collectSettings()) {
    const result = await call('update_settings', [values]);
    if (result) { state.settings = values; state.settingsDirty = false; }
    return !!result;
  }
  function setting(name) { return text(collectSettings()[name]).trim(); }
  function updateSetting(name, value) {
    const input = $$('[data-setting]').find(node => node.dataset.setting === name);
    if (input) input.value = text(value);
    state.settings[name] = text(value);
    refreshSummaries();
  }
  function shortDate(tag) {
    const match = /^dr-(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/.exec(tag);
    if (!match) return tag;
    const date = new Date(match[1] + '-' + match[2] + '-' + match[3] + 'T' + match[4] + ':' + match[5] + ':' + match[6] + 'Z');
    return date.toLocaleString('it-IT', { day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit' });
  }
  function refreshSummaries() {
    const settings = collectSettings();
    const host = text(settings.host).trim(), infisicalHost = text(settings.infisical_host).trim(), user = text(settings.user).trim();
    $('#stack-address').textContent = host || 'Nessuna destinazione';
    $('#infisical-address').textContent = infisicalHost || 'Nessuna destinazione';
    $('#stack-status').textContent = text(state.machines.stack && state.machines.stack.title, host && user ? 'Accessi inseriti' : 'Da configurare');
    $('#infisical-status').textContent = text(state.machines.infisical && state.machines.infisical.title, infisicalHost && settings.infisical_user ? 'Accessi inseriti' : 'Da configurare');
    [['stack', '#stack-status'], ['infisical', '#infisical-status']].forEach(([role, selector]) => {
      const info = state.machines[role];
      if (info && typeof info.detail === 'string') $(selector).closest('.environment-card').querySelector('p').textContent = info.detail;
    });
    $('#service-destination-context').textContent = host ? (user ? user + '@' : '') + host : 'VM stack da configurare';
    $('#service-vm-summary').textContent = host || 'Nessuna VM configurata';
    $('#service-user-summary').textContent = host && user ? 'Utente SSH: ' + user + ' · accessi condivisi con il recupero' : 'Completa gli accessi SSH della VM stack.';
    if (!state.service.rootEdited && /^[A-Za-z_][A-Za-z0-9_-]*$/.test(user)) $('#service-stack-root').value = '/home/' + user + '/streams-aio';
    if (!$('#service-project-id').value && settings.project_id) $('#service-project-id').value = settings.project_id;
    if (!$('#service-environment').value && settings.environment) $('#service-environment').value = settings.environment;
    if (state.point) {
      $('#backup-summary-date').textContent = shortDate(state.point.tag);
      $('#backup-summary-tag').textContent = state.point.tag;
      $('#backup-status').textContent = state.point.aio_snapshot ? 'Copia completa' : 'Da verificare';
      $('#backup-status').className = 'badge ' + (state.point.aio_snapshot ? 'ready' : 'warning');
      $('#recovery-selection').textContent = state.point.tag + (state.point.aio_snapshot ? ' · Configurazioni AIO incluse' : ' · Controlla il formato del backup');
    }
    renderServiceContext();
  }
  function navigate(page) {
    if (!PAGE_TITLES[page]) return;
    state.page = page;
    $$('[data-view]').forEach(node => { node.hidden = node.dataset.view !== page; });
    $$('.nav-item').forEach(button => {
      const active = button.dataset.page === page;
      button.classList.toggle('active', active);
      if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    });
    $('#breadcrumb-page').textContent = PAGE_TITLES[page];
    $('#main-content').scrollTop = 0;
    refreshSummaries();
  }

  function renderBusy() {
    const locked = busy();
    $$('input,textarea,select,[data-choose],#load-backups,#save-settings,#save-advanced,#recover-fresh,#recover-resume,#prepare-lab,#store-private,.scope-switch button').forEach(node => { node.disabled = locked; });
    $('#cancel-operation').hidden = !locked;
    if (!locked) $('#cancel-operation').disabled = false;
    const loadingButton = state.operation === 'lab' ? $('#prepare-lab') : state.operation === 'backups' ? $('#load-backups') : null;
    ['prepare-lab', 'load-backups'].forEach(id => $('#' + id).classList.toggle('loading', locked && $('#' + id) === loadingButton));
    renderServiceActions();
  }
  function resetStages(local = false) {
    state.stages = {};
    Object.keys(STAGES).forEach(key => { state.stages[key] = local && (key === 'GITHUB' || key === 'BACKUP') ? 'skipped' : 'pending'; });
    renderStages();
  }
  function stageRow(key, tone) {
    const row = element('div', 'verification-row ' + tone);
    row.dataset.stage = key;
    row.append(element('span', 'check-symbol', tone === 'pass' ? '✓' : tone === 'skipped' ? '−' : ''));
    row.append(element('span', 'check-label', STAGES[key]));
    row.append(element('small', '', STATUS_LABELS[tone]));
    return row;
  }
  function renderStages() {
    const serviceRows = [], operationRows = [];
    Object.keys(STAGES).forEach(key => {
      const tone = state.stages[key] || 'pending';
      serviceRows.push(stageRow(key, tone)); operationRows.push(stageRow(key, tone));
    });
    $('#service-verification').replaceChildren(...serviceRows);
    $('#operation-stages').replaceChildren(...operationRows);
    renderPhases();
  }
  function renderPhases() {
    $('#recovery-phases').replaceChildren(...PHASES.map(([label, key]) => {
      const tone = state.phases[key] || 'pending';
      const tile = element('div', 'phase-tile ' + tone);
      tile.append(element('span', 'phase-dot'), element('strong', '', label), element('small', '', state.phaseLabels[key] || STATUS_LABELS[tone]));
      return tile;
    }));
    const completed = PHASES.filter(([, key]) => state.phases[key] === 'pass').length;
    $('#recovery-count').textContent = completed ? completed + ' di ' + PHASES.length + ' verificati' : 'In attesa';
  }
  function groupedStage(stage) {
    if (STAGES[stage]) return stage;
    if (stage === 'DEPENDENCIES' || stage === 'PREFLIGHT') return 'HOST';
    if (stage.startsWith('INFISICAL_')) return 'INFISICAL';
    if (stage === 'NATIVE_AGENT') return 'AGENT';
    if (['STARTED', 'IMAGES', 'APPLICATION_CHECKS', 'OPERATIONAL_READY'].includes(stage)) return 'SERVICE';
    if (['PUBLIC_DOMAINS', 'TLS', 'COMETNET_TRIAL', 'LOCAL_ENDPOINTS', 'PUBLIC_CONTROLLERS', 'TAILSCALE', 'HEADPLANE'].includes(stage)) return 'DOMAINS';
    if (stage === 'AIO' || stage === 'AIO_BACKUP') return 'AIO';
    if (['CLONES', 'DOWNLOAD', 'DECRYPT', 'INITIALIZE', 'INPUTS', 'RENDER', 'EMPTY_STATE', 'RUNTIME_PROFILE', 'NPM', 'NPM_TOPOLOGY', 'PREPARED', 'STACK_TRANSFER', 'OPERATIONAL_PROFILE'].includes(stage)) return 'FILES';
    return null;
  }
  function recordRecoveryPhase(stage, status) {
    let key = stage === 'REFUSED' ? state.activePhase : null;
    if (!key) {
      const phase = PHASES.find(([name]) => Array.isArray(state.phaseStages[name]) && state.phaseStages[name].includes(stage));
      key = phase ? phase[1] : null;
    }
    if (!key) return null;
    state.activePhase = key;
    let tone = 'running', label = 'In corso';
    if (stage === 'EXTERNAL_UPSTREAMS' && status === 'WARNING') { tone = 'pending'; label = 'Collegamenti esterni da verificare'; }
    else if (['REFUSED', 'FAILED', 'ERROR'].includes(status)) { tone = 'failed'; label = 'Da risolvere'; }
    else if (status === 'SKIPPED') { tone = 'pending'; label = 'Non completato'; }
    else if (status === 'PASS' && state.finishedStages.has(stage)) { tone = 'pass'; label = 'Verificato'; }
    else if (status === 'PASS') label = 'Controllo superato';
    state.phases[key] = tone; state.phaseLabels[key] = label;
    return { key, tone, label };
  }
  function addActivity(title, description = '', tone = 'pending') {
    state.history.unshift({ title, description, tone, time: new Date() });
    state.history = state.history.slice(0, 80);
    $('#activity-list').replaceChildren(...state.history.slice(0, 18).map(item => {
      const row = element('div', 'activity-row');
      row.append(element('span', 'status-dot ' + item.tone));
      const content = element('div', '', item.title);
      if (item.description) content.append(element('small', '', item.description));
      row.append(content, element('span', 'activity-time', item.time.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })));
      return row;
    }));
  }

  async function startJob(operation, method, args, title, options = {}) {
    if (busy()) { showError(fixedError('SERVICE_OPERATION_BUSY', 'È già in corso un’operazione. Attendi l’esito oppure interrompila prima di avviarne un’altra.')); return; }
    state.operation = operation; state.submitting = true;
    if (operation === 'service' || operation === 'inspect' || operation === 'lab') resetStages(operation === 'lab' || state.service.scope === 'local_lab');
    if (operation === 'recovery') { state.phases = {}; state.phaseLabels = {}; state.activePhase = null; renderPhases(); }
    setGlobal(title, 'Avvio della richiesta. Le credenziali restano in questa sessione.', 'running');
    if (operation === 'lab') feedback('lab-feedback', 'Controllo degli accessi e del backup selezionato in corso.');
    if (operation === 'service' || operation === 'inspect') feedback('service-feedback', title);
    renderBusy();
    let result = null;
    // Both the execution payload and SSH settings were captured by the click
    // handler before any await. Keep all controls locked throughout the flush.
    if (!options.syncSettings || await flushSettings(options.settings)) result = await call(method, args);
    state.submitting = false;
    if (result && result.job_id) state.backendBusy = true;
    else state.backendBusy = false;
    renderBusy();
  }
  async function runSynchronous(action) {
    if (busy()) return null;
    state.submitting = true; renderBusy();
    try { return await action(); }
    finally { state.submitting = false; renderBusy(); }
  }
  async function saveSettings() {
    const result = await runSynchronous(async () => await flushSettings());
    if (result) { setGlobal('Impostazioni conservate', 'Gli accessi sono disponibili in questa sessione. Nessun file di credenziali è stato salvato.'); refreshSummaries(); }
  }
  async function chooseFile(kind) {
    if (busy() || !FILE_KINDS.has(kind)) return;
    const result = await call('choose_file', [kind]);
    if (result && typeof result.path === 'string' && result.path) {
      updateSetting(kind, result.path); state.settingsDirty = true; state.service.inspected = false; renderServiceActions();
    }
  }

  function draftPayload() {
    const privateValues = Object.create(null);
    state.service.privateNames.forEach(name => {
      if (Object.prototype.hasOwnProperty.call(state.service.privateValues, name)) privateValues[name] = state.service.privateValues[name];
    });
    return { compose: $('#service-compose').value, env: $('#service-env').value, service_name: $('#service-name').value.trim(),
      private_names: Array.from(state.service.privateNames).sort(), private_values: privateValues, reviewed: $('#service-reviewed').checked };
  }
  function executionPayload() {
    return { stack_root: $('#service-stack-root').value.trim(), probe_url: $('#service-probe-url').value.trim(),
      verification_scope: state.service.scope, infisical: { endpoint: $('#service-infisical-endpoint').value.trim(),
        project_id: $('#service-project-id').value.trim(), environment: $('#service-environment').value.trim(), access_token: $('#service-access-token').value } };
  }
  function clearPlan(resetInventory = false) {
    state.service.plan = null; state.service.inspected = false; state.service.completed = false;
    $('#service-reviewed').checked = false;
    if (resetInventory) { state.service.analyzed = false; state.service.variables = []; state.service.privateNames.clear(); state.service.privateValues = Object.create(null); state.service.selectedVariable = ''; }
    // analyze_service and prepare_service invalidate the stored draft before
    // replacing it. A separate background invalidation could race the prepare.
    renderServiceActions();
  }
  function setScope(scope) {
    state.service.scope = scope === 'local_lab' ? 'local_lab' : 'full';
    $$('[name="verification-scope"]').forEach(input => {
      input.checked = input.value === state.service.scope;
      input.closest('.choice-card').classList.toggle('selected', input.checked);
    });
    state.service.inspected = false;
    $('#lab-panel').hidden = state.service.scope !== 'local_lab';
    renderServiceContext(); renderServiceActions(); renderPlan();
  }
  function renderServiceContext() {
    $('#service-scope-context').textContent = state.service.scope === 'local_lab' ? 'Collaudo locale · GitHub e backup esclusi' : 'Percorso completo · GitHub e backup inclusi';
  }
  function selectStep(step) {
    if (busy()) return;
    if (step === 2 && !state.service.analyzed) return;
    if (step === 3 && !state.service.plan) return;
    state.service.step = Math.max(0, Math.min(3, step));
    $$('[data-step-panel]').forEach(node => { node.hidden = Number(node.dataset.stepPanel) !== state.service.step; });
    $$('.step').forEach(button => {
      const index = Number(button.dataset.step), active = index === state.service.step;
      button.classList.toggle('active', active); button.classList.toggle('complete', index < state.service.step);
      if (active) button.setAttribute('aria-current', 'step'); else button.removeAttribute('aria-current');
    });
    $('.service-workspace').scrollTop = 0;
    renderServiceActions();
  }
  function renderServiceActions() {
    const step = state.service.step, locked = busy();
    $('#service-back').disabled = locked || step === 0;
    $('#service-next').hidden = step === 3;
    $('#service-next').disabled = locked || (step === 2 && !$('#service-reviewed').checked);
    const nextLabel = step === 1 ? 'Analizza variabili' : step === 2 ? 'Prepara il piano' : 'Continua';
    $('#service-next').replaceChildren(document.createTextNode(nextLabel), icon('arrow'));
    $('#inspect-service').hidden = step !== 3 || state.service.completed;
    $('#inspect-service').disabled = locked || !state.service.plan;
    $('#apply-service').hidden = step !== 3 || state.service.completed;
    $('#apply-service').disabled = locked || !state.service.inspected;
    $$('.step').forEach(button => { const index = Number(button.dataset.step); button.disabled = locked || (index === 2 && !state.service.analyzed) || (index === 3 && !state.service.plan); });
    const hints = [ 'La destinazione viene verificata prima di qualsiasi aggiunta.', 'L’analisi è locale. Nessuna VM viene modificata.', 'I valori privati non entrano nel piano o negli esiti.', state.service.scope === 'local_lab' ? 'Solo servizio e Agent. Nessuna pubblicazione.' : 'Il completamento include GitHub e backup verificati.' ];
    $('#service-action-hint').textContent = hints[step];
  }
  function renderVariables() {
    const variables = state.service.variables;
    $('#variable-count').textContent = variables.length + (variables.length === 1 ? ' variabile' : ' variabili');
    $('#variables-empty').hidden = variables.length > 0;
    $('#variables-empty').textContent = state.service.analyzed ? 'Questo servizio non richiede variabili da classificare.' : 'Analizza prima il Compose e le variabili nel passo Servizio.';
    $('#variable-rows').replaceChildren(...variables.map(variable => {
      const name = variable.name, isPrivate = state.service.privateNames.has(name);
      const row = element('tr', state.service.selectedVariable === name ? 'selected' : '');
      row.append(element('td', '', name));
      const source = element('td'); source.append(element('span', 'source-badge', SOURCE_LABELS[variable.source] || 'Variabile')); row.append(source);
      const scopeCell = element('td'), toggle = element('div', 'scope-switch');
      [['Pubblica', false], ['Infisical', true]].forEach(([label, privateScope]) => {
        const button = element('button', privateScope === isPrivate ? 'active' : '', label);
        button.type = 'button'; button.disabled = busy(); button.setAttribute('aria-pressed', String(privateScope === isPrivate));
        button.addEventListener('click', event => { event.stopPropagation(); changeClassification(name, privateScope); });
        toggle.append(button);
      });
      scopeCell.append(toggle); row.append(scopeCell);
      const provided = Object.prototype.hasOwnProperty.call(state.service.privateValues, name);
      const label = provided ? 'In memoria' : variable.has_value ? 'Nel testo' : 'Da inserire';
      const valueCell = element('td'); valueCell.append(element('span', 'value-state' + (!provided && !variable.has_value ? ' missing' : ''), label)); row.append(valueCell);
      row.addEventListener('click', () => { state.service.selectedVariable = name; $('#private-value').value = ''; renderVariables(); });
      return row;
    }));
    const selectedPrivate = state.service.privateNames.has(state.service.selectedVariable);
    $('#secret-editor').hidden = !selectedPrivate;
    $('#secret-editor-title').textContent = selectedPrivate ? state.service.selectedVariable : 'Valore privato';
    $('#service-infisical-panel').hidden = !privateRequired();
    renderServiceActions();
  }
  function changeClassification(name, isPrivate) {
    if (busy()) return;
    if (isPrivate) state.service.privateNames.add(name);
    else { state.service.privateNames.delete(name); delete state.service.privateValues[name]; }
    state.service.selectedVariable = name; $('#private-value').value = ''; clearPlan(); renderVariables();
  }
  async function analyzeService() {
    const result = await runSynchronous(() => call('analyze_service', [{ compose: $('#service-compose').value, env: $('#service-env').value, service_name: $('#service-name').value.trim() }]));
    if (!result) return;
    state.service.variables = Array.isArray(result.variables) ? result.variables.filter(v => v && typeof v.name === 'string') : [];
    state.service.privateNames = new Set(state.service.variables.filter(v => v.suggested_private === true).map(v => v.name));
    state.service.privateValues = Object.create(null); state.service.selectedVariable = '';
    state.service.analyzed = true; state.service.plan = null; state.service.inspected = false;
    $('#service-reviewed').checked = false; renderVariables(); selectStep(2);
    setGlobal('Variabili analizzate', 'Verifica le proposte pubblico/privato prima di preparare il piano.');
  }
  function storePrivateValue() {
    const name = state.service.selectedVariable;
    if (busy() || !state.service.privateNames.has(name)) return;
    state.service.privateValues[name] = $('#private-value').value;
    $('#private-value').value = ''; clearPlan(); renderVariables();
    setGlobal('Valore privato inserito', 'Conservato soltanto in memoria. Non viene mostrato nel piano o negli esiti.');
  }
  async function prepareService() {
    if (!$('#service-reviewed').checked) { showError(fixedError('SERVICE_REVIEW_REQUIRED', 'Verifica la scelta pubblico/privato delle variabili prima di preparare il piano.')); return; }
    const result = await runSynchronous(() => call('prepare_service', [draftPayload()]));
    if (!result || !result.plan || typeof result.plan !== 'object') return;
    state.service.plan = result.plan; state.service.inspected = false; state.service.completed = false;
    feedback('service-feedback', ''); resetStages(state.service.scope === 'local_lab'); renderPlan(); selectStep(3);
    setGlobal('Piano pronto', 'Verifica la VM. L’aggiunta richiede poi un tuo comando esplicito.');
  }
  function renderPlan() {
    const plan = state.service.plan;
    $('#plan-service-name').textContent = plan ? text(plan.service_name, 'Servizio') : 'Piano da preparare';
    $('#plan-image').textContent = plan ? text(plan.image) : 'Completa i passaggi precedenti.';
    $('#plan-scope-badge').textContent = state.service.completed ? 'Verificato' : state.service.inspected ? 'VM verificata' : plan ? (state.service.scope === 'local_lab' ? 'Collaudo locale' : 'Piano pronto') : 'Da verificare';
    $('#plan-scope-badge').className = 'badge ' + (state.service.completed ? 'ready' : plan ? 'brand' : 'neutral');
    const files = [];
    if (plan) {
      const rows = [['file', 'Variabili pubbliche', plan.public_env_path]];
      if (privateRequired()) rows.push(['lock', 'Variabili private da Agent', plan.private_env_path]);
      rows.forEach(([symbol, label, path]) => {
        const row = element('div', 'plan-file'), content = element('div');
        content.append(element('strong', '', label), element('span', '', text(path)));
        row.append(icon(symbol), content); files.push(row);
      });
    }
    $('#plan-files').replaceChildren(...files);
    $('#plan-json').textContent = plan ? JSON.stringify(plan, null, 2) : 'Nessun piano preparato.';
  }
  async function nextServiceStep() {
    if (state.service.step === 0) selectStep(1);
    else if (state.service.step === 1) await analyzeService();
    else if (state.service.step === 2) await prepareService();
  }
  async function inspectService() {
    if (busy() || !state.service.plan) return;
    const payload = executionPayload(), settings = collectSettings();
    state.service.inspected = false;
    await startJob('inspect', 'inspect_service', [payload], 'Verifica della VM in corso', { syncSettings: true, settings });
  }
  async function applyService() {
    if (busy() || !state.service.plan || !state.service.inspected) return;
    const payload = executionPayload(), settings = collectSettings();
    await startJob('service', 'apply_service', [payload], state.service.scope === 'local_lab' ? 'Aggiunta e collaudo locale in corso' : 'Aggiunta e verifica completa in corso', { syncSettings: true, settings });
  }

  function showHostKey(event) {
    state.hostKeys.push(event);
    displayNextHostKey();
  }
  function displayNextHostKey() {
    if (state.activeHostKey || !state.hostKeys.length) return;
    state.activeHostKey = state.hostKeys.shift();
    const item = state.activeHostKey;
    $('#host-key-title').textContent = item.changed ? 'La VM ha una nuova identità.' : 'Verifica l’identità della VM.';
    $('#host-key-endpoint').textContent = text(item.endpoint);
    $('#host-key-fingerprint').textContent = text(item.fingerprint);
    $('#host-key-previous').textContent = text(item.previous);
    $('#previous-key-row').hidden = !item.previous;
    $('#host-key-dialog').showModal();
  }
  async function answerHostKey(approved) {
    const item = state.activeHostKey;
    if (!item) return;
    $('#host-key-dialog').close(); state.activeHostKey = null;
    await call('answer_host_key', [item.id, approved]);
    displayNextHostKey();
  }
  function completeService(event) {
    const checks = event.checks || {};
    const local = event.status === 'PASS_LOCAL' && checks.service === true && checks.agent === true && checks.github === false && checks.backup === false;
    const full = event.status === 'PASS' && checks.service === true && checks.agent === true && checks.github === true && checks.backup === true && /^[a-f0-9]{40}$/.test(text(event.public_commit)) && /^dr-\d{8}T\d{6}Z$/.test(text(event.backup_tag));
    if ((state.service.scope === 'local_lab' && !local) || (state.service.scope !== 'local_lab' && !full)) { showError(fixedError('SERVICE_OPERATION_INCOMPLETE', 'L’esito non contiene tutti i controlli richiesti. Conserva gli esiti e verifica di nuovo la VM.')); return; }
    state.service.completed = true; state.service.inspected = false;
    Object.keys(STAGES).forEach(stage => { state.stages[stage] = local && ['GITHUB', 'BACKUP'].includes(stage) ? 'skipped' : 'pass'; });
    const title = local ? 'Collaudo locale completato' : 'Servizio aggiunto e verificato';
    const description = local ? 'Servizio e Agent verificati. GitHub e backup non eseguiti.' : 'GitHub aggiornato. Backup cifrato verificato: ' + event.backup_tag + '.';
    feedback('service-feedback', title + '\n' + description, 'success'); setGlobal(title, description, 'pass'); addActivity(title, description, 'pass');
    state.service.privateValues = Object.create(null); $('#private-value').value = ''; $('#service-access-token').value = '';
    renderStages(); renderPlan(); renderServiceActions();
  }
  function processEvent(event) {
    if (!event || typeof event.kind !== 'string') return;
    if (event.kind === 'stage') {
      const rawStage = text(event.stage), stage = groupedStage(rawStage), tone = statusTone(event.status);
      const display = text(state.progressText[event.code], text(state.labels[rawStage], STAGES[stage] || rawStage));
      const code = text(event.code), description = display + ' · ' + STATUS_LABELS[tone] + (code ? ' · ' + code : '');
      if (state.operation === 'recovery') {
        const phase = recordRecoveryPhase(rawStage, event.status);
        if (phase && STAGES[phase.key]) state.stages[phase.key] = phase.tone;
      } else if (stage && STAGES[stage]) state.stages[stage] = state.service.scope === 'local_lab' && ['GITHUB', 'BACKUP'].includes(stage) ? 'skipped' : tone;
      setGlobal(tone === 'failed' ? 'Operazione da verificare' : 'Operazione in corso', description, tone === 'failed' ? 'failed' : 'running');
      if (state.operation === 'lab') feedback('lab-feedback', description, tone === 'failed' ? 'error' : '');
      addActivity(display, code, tone); renderStages();
    } else if (event.kind === 'error') {
      state.service.inspected = false; showError(event);
    } else if (event.kind === 'done') {
      state.backendBusy = false; state.submitting = false; renderBusy();
    } else if (event.kind === 'choices') {
      const tags = Array.isArray(event.tags) ? event.tags.filter(tag => typeof tag === 'string' && /^dr-\d{8}T\d{6}Z$/.test(tag)) : [];
      const options = tags.map(tag => { const option = element('option', '', tag); option.value = tag; return option; });
      if (!options.length) { const option = element('option', '', 'Nessun backup disponibile'); option.value = ''; options.push(option); }
      $('#backup-tag').replaceChildren(...options);
      setGlobal('Backup caricati', tags.length + ' punti di recupero disponibili. Seleziona la copia da usare.');
    } else if (event.kind === 'point') {
      state.point = { tag: text(event.tag), public_commit: text(event.public_commit), aio_snapshot: event.aio_snapshot === true };
      updateSetting('dr_tag', state.point.tag); updateSetting('public_commit', state.point.public_commit); refreshSummaries();
      setGlobal('Backup selezionato', state.point.tag + ' · Commit associato verificato.');
    } else if (event.kind === 'lab_prepared') {
      if (event.status !== 'PREPARED_LAB') { showError(fixedError('SERVICE_LAB_PREPARATION_INCOMPLETE', 'La preparazione non ha restituito un esito verificato.')); return; }
      setScope('local_lab');
      if (typeof event.stack_root === 'string') { $('#service-stack-root').value = event.stack_root; state.service.rootEdited = true; }
      const message = 'File e Agent preparati. Stack completo non avviato: puoi aggiungere un servizio di prova. GitHub e backup restano esclusi.';
      feedback('lab-feedback', message, 'success'); setGlobal('VM di collaudo preparate', message, 'pass'); addActivity('Laboratorio preparato', message, 'pass');
    } else if (event.kind === 'inspected') {
      state.service.inspected = true; feedback('service-feedback', 'VM verificata. Premi Aggiungi e verifica per applicare questo piano.');
      setGlobal('VM verificata', 'Il piano può essere applicato con Aggiungi e verifica.'); renderPlan(); renderServiceActions();
    } else if (event.kind === 'completed') {
      if (event.operation === 'service') completeService(event);
      else {
        setGlobal('Percorso di recupero completato', 'Consulta gli esiti verificati e i collegamenti esterni ancora da controllare.', 'pass');
        addActivity('Percorso di recupero completato', 'Gli esiti indicano i controlli effettivamente verificati.', 'pass');
      }
    } else if (event.kind === 'host_key') showHostKey(event);
    else if (event.kind === 'detected') {
      ['stack', 'infisical'].forEach(role => {
        const info = event[role];
        if (info && typeof info.title === 'string' && typeof info.detail === 'string') state.machines[role] = { title: info.title, detail: info.detail };
      });
      refreshSummaries();
      addActivity('Destinazioni rilevate', 'Proprietà e punto di recupero vengono verificati prima di continuare.');
    }
    else if (event.kind === 'resumed_selection') {
      const point = event.point;
      if (point && typeof point.tag === 'string' && typeof point.public_commit === 'string' && typeof point.aio_snapshot === 'boolean') {
        state.point = { tag: point.tag, public_commit: point.public_commit, aio_snapshot: point.aio_snapshot };
        if (!Array.from($('#backup-tag').options).some(option => option.value === point.tag)) {
          const option = element('option', '', point.tag); option.value = point.tag; $('#backup-tag').append(option);
        }
        updateSetting('dr_tag', point.tag); updateSetting('public_commit', point.public_commit);
      }
      if (typeof event.routing_mode === 'string') updateSetting('routing_mode', event.routing_mode);
      if (typeof event.domain_target_address === 'string') updateSetting('domain_target_address', event.domain_target_address);
      refreshSummaries();
      addActivity('Punto di ripresa rilevato', 'Si usa il backup associato al tentativo già presente sulle VM.');
    }
  }
  async function poll() {
    if (!state.initialized || state.pollInFlight || !api()) return;
    state.pollInFlight = true;
    try {
      const response = await call('poll', [], true);
      if (response) {
        state.backendBusy = response.busy === true;
        if (Array.isArray(response.events)) response.events.forEach(processEvent);
        renderBusy();
      }
    } finally { state.pollInFlight = false; }
  }
  async function initializeBridge() {
    if (state.initialized || !api()) return;
    const result = await call('initialize');
    if (!result) return;
    state.initialized = true; state.version = text(result.version); state.errors = result.errors || {}; state.labels = result.stages || {}; state.progressText = result.progress_text || {};
    state.phaseStages = result.phase_stages || {};
    state.finishedStages = new Set(Array.isArray(result.finished_stages) ? result.finished_stages.filter(stage => typeof stage === 'string') : []);
    $('#version-label').textContent = state.version ? 'v' + state.version : 'Desktop';
    $('#preview-banner').hidden = true; document.body.dataset.bridgeState = 'connected';
    syncSettings(result.defaults || {}); window.recoveryUI.ready = true;
    void poll();
  }

  function bindEvents() {
    $$('.nav-item').forEach(button => button.addEventListener('click', () => navigate(button.dataset.page)));
    $$('[data-navigate]').forEach(button => button.addEventListener('click', () => navigate(button.dataset.navigate)));
    $$('[data-setting]').forEach(input => input.addEventListener('input', () => { state.settingsDirty = true; state.service.inspected = false; refreshSummaries(); renderServiceActions(); }));
    $$('.toggle-password').forEach(button => button.addEventListener('click', () => { const input = button.parentElement.querySelector('input'); input.type = input.type === 'password' ? 'text' : 'password'; button.setAttribute('aria-pressed', String(input.type === 'text')); }));
    $$('[data-choose]').forEach(button => button.addEventListener('click', () => void chooseFile(button.dataset.choose)));
    $('#save-settings').addEventListener('click', () => void saveSettings()); $('#save-advanced').addEventListener('click', () => void saveSettings());
    $('#load-backups').addEventListener('click', () => void startJob('backups', 'load_backups', [collectSettings()], 'Caricamento backup da GitHub'));
    $('#backup-tag').addEventListener('change', () => { if ($('#backup-tag').value) void startJob('point', 'load_backup', [$('#backup-tag').value], 'Verifica del punto di recupero'); });
    $('#recover-fresh').addEventListener('click', () => void startJob('recovery', 'recover', [collectSettings(), 'fresh'], 'Preparazione del recupero da zero'));
    $('#recover-resume').addEventListener('click', () => void startJob('recovery', 'recover', [collectSettings(), 'resume'], 'Rilevamento del recupero esistente'));
    $('#prepare-lab').addEventListener('click', () => void startJob('lab', 'prepare_lab', [collectSettings()], 'Preparazione delle VM di collaudo'));
    $$('[name="verification-scope"]').forEach(input => input.addEventListener('change', () => { if (input.checked) setScope(input.value); }));
    $$('.step').forEach(button => button.addEventListener('click', () => selectStep(Number(button.dataset.step))));
    $('#service-back').addEventListener('click', () => selectStep(state.service.step - 1));
    $('#service-next').addEventListener('click', () => void nextServiceStep());
    $('#store-private').addEventListener('click', storePrivateValue);
    $('#service-reviewed').addEventListener('change', renderServiceActions);
    ['service-compose', 'service-env', 'service-name'].forEach(id => $('#' + id).addEventListener('input', () => { clearPlan(true); renderVariables(); }));
    ['service-stack-root', 'service-probe-url', 'service-project-id', 'service-environment', 'service-access-token', 'service-infisical-endpoint'].forEach(id => $('#' + id).addEventListener('input', () => { state.service.inspected = false; if (id === 'service-stack-root') state.service.rootEdited = true; renderServiceActions(); }));
    $('#inspect-service').addEventListener('click', () => void inspectService()); $('#apply-service').addEventListener('click', () => void applyService());
    $('#cancel-operation').addEventListener('click', async () => { $('#cancel-operation').disabled = true; setGlobal('Interruzione richiesta', 'Attendi la chiusura del passaggio in corso. Lo stato sulle VM resta conservato.', 'running'); if (state.operation === 'lab') feedback('lab-feedback', 'Interruzione richiesta. Attendo la chiusura del passaggio sulle VM di collaudo.'); await call('cancel'); });
    $('#show-operation-details').addEventListener('click', () => { $('#operation-details').hidden = !$('#operation-details').hidden; });
    $('#close-operation-details').addEventListener('click', () => { $('#operation-details').hidden = true; });
    $$('.save-report').forEach(button => button.addEventListener('click', async () => { const result = await call('save_report'); if (result && result.path) setGlobal('Esiti salvati', 'Il report contiene solo gli esiti previsti, senza credenziali.'); }));
    $('#help-button').addEventListener('click', () => $('#help-dialog').showModal()); $('#close-help').addEventListener('click', () => $('#help-dialog').close());
    $('#host-key-approve').addEventListener('click', () => void answerHostKey(true)); $('#host-key-reject').addEventListener('click', () => void answerHostKey(false));
    $('#host-key-dialog').addEventListener('cancel', event => { event.preventDefault(); void answerHostKey(false); });
    $$('.code-field textarea').forEach(input => input.addEventListener('keydown', event => { if (event.key === 'Tab' && !event.shiftKey) { event.preventDefault(); const start = input.selectionStart, end = input.selectionEnd; input.setRangeText('  ', start, end, 'end'); input.dispatchEvent(new Event('input', { bubbles: true })); } }));
  }
  function initializeUI() {
    bindEvents(); syncSettings({ user: 'test', infisical_user: 'test2', port: '22', infisical_port: '22', routing_mode: 'parallel_test' });
    resetStages(); renderVariables(); renderPlan(); renderServiceActions(); window.recoveryUI.ready = true;
    if (api()) void initializeBridge();
    else { document.body.dataset.bridgeState = 'preview'; $('#preview-banner').hidden = false; }
    window.setInterval(() => void poll(), 550);
  }

  window.__uiSelfTest = async () => {
    const checks = [
      { name: 'four-main-pages', ok: $$('[data-view]').length === 4 },
      { name: 'four-service-steps', ok: $$('[data-step-panel]').length === 4 && $$('.step').length === 4 },
      { name: 'persistent-feedback', ok: !$('#main-content').contains($('#statusbar')) && !!$('#global-status-detail') },
      { name: 'masked-credentials', ok: $$('[data-setting="password"],[data-setting="infisical_password"],[data-setting="github_token"],#private-value,#service-access-token').every(input => input.type === 'password' && input.autocomplete === 'off') },
      { name: 'bounded-file-choices', ok: $$('[data-choose]').every(button => FILE_KINDS.has(button.dataset.choose)) },
      { name: 'no-inline-handlers', ok: $$('*').every(node => Array.from(node.attributes).every(attr => !/^on/i.test(attr.name))) },
      { name: 'desktop-ready', ok: window.recoveryUI.ready === true },
      { name: 'native-bridge-connected', ok: state.initialized && document.body.dataset.bridgeState === 'connected' && typeof api().prepare_lab === 'function' }
    ];
    return { ok: checks.every(check => check.ok), checks };
  };
  window.addEventListener('pywebviewready', () => void initializeBridge());
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initializeUI); else initializeUI();
})();
