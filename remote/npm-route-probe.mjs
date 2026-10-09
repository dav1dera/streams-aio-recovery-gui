// Prove every enabled local HTTPS proxy domain reaches this replacement NPM.
// The caller supplies exact routing rows from the verified private topology.
// Only temporary nonce locations are changed; the private journal reconciles
// interruption without overwriting an unrelated operator change.
import fs from 'node:fs';
const output = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
process.stderr.write = () => true;
const journal = '/data/.streams-aio-route-probe.json';
const requireCondition = value => { if (!value) throw new Error('REFUSED'); };
const sorted = value => Array.isArray(value) ? value.map(sorted)
  : value !== null && typeof value === 'object'
    ? Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const equal = (a, b) => JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));
const routing = row => ({domain_names: row.domain_names, forward_host: row.forward_host,
  forward_port: Number(row.forward_port), forward_scheme: row.forward_scheme,
  locations: row.locations || [], advanced_config: row.advanced_config || ''});
const markerConfig = (before, nonce) => before + `\n# streams-aio-recovery-route-proof\nlocation = /.well-known/streams-aio-recovery/${nonce} {\n  auth_basic off;\n  auth_request off;\n  allow all;\n  default_type text/plain;\n  return 200 '${nonce}';\n}\n`;
try {
  let raw = ''; for await (const chunk of process.stdin) raw += chunk;
  const input = JSON.parse(raw);
  requireCondition(['install', 'remove'].includes(input.action));
  requireCondition(JSON.parse(fs.readFileSync('/app/package.json')).version === '2.16.0');
  const {default: hosts} = await import('/app/models/proxy_host.js');
  const {default: nginx} = await import('/app/internal/nginx.js');
  const readHost = id => hosts.query().findById(id).allowGraph(hosts.defaultAllowGraph)
    .withGraphFetched(`[${hosts.defaultExpand.join(', ')}]`);
  const render = async ids => {
    for (const id of ids) await nginx.generateConfig('proxy_host', await readHost(id));
    if (ids.length) { await nginx.test(); await nginx.reload(); }
  };
  const remove = async () => {
    if (!fs.existsSync(journal)) return;
    const info = fs.lstatSync(journal);
    requireCondition(info.isFile() && !info.isSymbolicLink() && info.nlink === 1
      && info.uid === 0 && (info.mode & 0o777) === 0o600);
    const saved = JSON.parse(fs.readFileSync(journal));
    requireCondition(equal(Object.keys(saved).sort(), ['nonce', 'rows', 'schema'])
      && saved.schema === 1 && /^[0-9a-f]{48}$/.test(saved.nonce)
      && Array.isArray(saved.rows) && saved.rows.length > 0 && saved.rows.length <= 4096);
    const ids = new Set();
    for (const item of saved.rows) {
      requireCondition(equal(Object.keys(item).sort(), ['after', 'before', 'id'])
        && Number.isInteger(item.id) && item.id > 0 && !ids.has(item.id)
        && typeof item.before === 'string' && item.after === markerConfig(item.before, saved.nonce));
      ids.add(item.id);
      const row = await readHost(item.id);
      requireCondition(row && !row.is_deleted && [item.before, item.after].includes(row.advanced_config || ''));
    }
    // Each item may be before or after after an interrupted multi-host update.
    // Every row is validated before restoring any of the marker locations.
    for (const item of saved.rows) {
      const row = await readHost(item.id);
      requireCondition([item.before, item.after].includes(row.advanced_config || ''));
      if ((row.advanced_config || '') !== item.before)
        await hosts.query().patchAndFetchById(item.id, {advanced_config: item.before});
    }
    await render([...ids]);
    fs.unlinkSync(journal);
  };
  await remove();
  if (input.action === 'remove') {
    output(JSON.stringify({status: 'PASS'}) + '\n');
    process.exit(0);
  } else {
    requireCondition(typeof input.nonce === 'string' && /^[0-9a-f]{48}$/.test(input.nonce)
      && Array.isArray(input.routes) && input.routes.length > 0 && input.routes.length <= 4096
      && Number.isInteger(input.cometnet_id) && input.cometnet_id > 0
      && typeof input.cometnet_hostname === 'string');
    const all = await hosts.query().where('is_deleted', 0);
    const changes = [], probes = [], ids = new Set();
    let disabled = 0, http = 0, cometnet = false;
    for (const expected of input.routes) {
      requireCondition(equal(Object.keys(expected).sort(), ['id', 'routing'])
        && Number.isInteger(expected.id) && expected.id > 0 && !ids.has(expected.id));
      ids.add(expected.id);
      const row = all.find(item => item.id === expected.id);
      requireCondition(row && equal(routing(row), expected.routing));
      if (!row.enabled) { disabled++; continue; }
      if (!row.certificate_id) { http++; continue; }
      requireCondition(Array.isArray(row.domain_names) && row.domain_names.length > 0);
      if (row.id === input.cometnet_id) {
        requireCondition(row.domain_names.includes(input.cometnet_hostname)
          && [1, true].includes(row.allow_websocket_upgrade));
        cometnet = true;
      }
      for (const domain of row.domain_names) {
        requireCondition(typeof domain === 'string'
          && /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain) && domain.includes('.'));
        requireCondition(all.filter(other => other.enabled && Array.isArray(other.domain_names)
          && other.domain_names.includes(domain)).length === 1);
        probes.push({id: row.id, hostname: domain});
      }
      const before = row.advanced_config || '';
      requireCondition(typeof before === 'string' && !before.includes('streams-aio-recovery-route-proof'));
      changes.push({id: row.id, before, after: markerConfig(before, input.nonce)});
    }
    requireCondition(cometnet && changes.length > 0 && probes.length <= 16384);
    fs.writeFileSync(journal, JSON.stringify({schema: 1, nonce: input.nonce, rows: changes}),
      {flag: 'wx', mode: 0o600});
    for (const item of changes) {
      requireCondition((await readHost(item.id)).advanced_config === item.before
        || !item.before && !(await readHost(item.id)).advanced_config);
      await hosts.query().patchAndFetchById(item.id, {advanced_config: item.after});
    }
    await render(changes.map(item => item.id));
    output(JSON.stringify({status: 'PASS', probes, hosts: changes.length,
      skipped_disabled: disabled, skipped_http: http}) + '\n');
    process.exit(0);
  }
} catch {
  output(JSON.stringify({status: 'FAIL', code: 'ROUTE_PROBE_REFUSED'}) + '\n');
  process.exit(1);
}
