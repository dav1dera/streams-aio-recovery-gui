// Replacement NPM only. A short-lived nonce proves DNS reaches this NPM,
// rather than a still-running original with the same domain and certificate.
import fs from 'node:fs';
const output = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
process.stderr.write = () => true;
const journal = '/data/.streams-aio-domain-probe.json';
const requireCondition = value => { if (!value) throw new Error('REFUSED'); };
try {
  let raw = ''; for await (const chunk of process.stdin) raw += chunk;
  const input = JSON.parse(raw);
  requireCondition(['install', 'remove'].includes(input.action));
  requireCondition(JSON.parse(fs.readFileSync('/app/package.json')).version === '2.16.0');
  const {default: hosts} = await import('/app/models/proxy_host.js');
  const {default: nginx} = await import('/app/internal/nginx.js');
  const readHost = id => hosts.query().findById(id).allowGraph(hosts.defaultAllowGraph)
    .withGraphFetched(`[${hosts.defaultExpand.join(', ')}]`);
  const render = async row => { await nginx.generateConfig('proxy_host', row); await nginx.test(); await nginx.reload(); };
  const markerConfig = (before, nonce) => before + `\n# streams-aio-recovery-proof\nlocation = /.well-known/streams-aio-recovery/${nonce} {\n  default_type text/plain;\n  return 200 '${nonce}';\n}\n`;
  const remove = async () => {
    if (!fs.existsSync(journal)) return;
    const info = fs.lstatSync(journal);
    requireCondition(info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && (info.mode & 0o777) === 0o600);
    const saved = JSON.parse(fs.readFileSync(journal));
    requireCondition(saved.schema === 1 && Number.isInteger(saved.id) && saved.id > 0
      && typeof saved.before === 'string' && typeof saved.after === 'string'
      && /^[0-9a-f]{48}$/.test(saved.nonce) && saved.after === markerConfig(saved.before, saved.nonce));
    let row = await readHost(saved.id);
    requireCondition(row && !row.is_deleted && row.enabled
      && [saved.before, saved.after].includes(row.advanced_config || ''));
    if ((row.advanced_config || '') !== saved.before) await hosts.query().patchAndFetchById(saved.id, {advanced_config: saved.before});
    row = await readHost(saved.id); await render(row);
    fs.unlinkSync(journal);
  };
  // Recover our own interrupted probe before creating another marker. Do not
  // overwrite a drifted host or an unrecognized journal.
  await remove();
  if (input.action === 'install') {
    requireCondition(typeof input.hostname === 'string' && /^[a-z0-9.-]+$/.test(input.hostname)
      && typeof input.nonce === 'string' && /^[0-9a-f]{48}$/.test(input.nonce)
      && Array.isArray(input.forward_hosts) && input.forward_hosts.length > 0
      && (input.kind === 'headscale' ? input.forward_port === 8080
        : input.kind === undefined && input.forward_port === 8765));
    const rows = (await hosts.query().where('is_deleted', 0).where('enabled', 1))
      .filter(row => Array.isArray(row.domain_names) && row.domain_names.includes(input.hostname));
    requireCondition(rows.length === 1 && rows[0].certificate_id > 0
      && (input.kind === 'headscale' || [1, true].includes(rows[0].allow_websocket_upgrade)));
    requireCondition(input.forward_hosts.includes(rows[0].forward_host)
      && Number(rows[0].forward_port) === input.forward_port && rows[0].forward_scheme === 'http');
    const row = rows[0], before = row.advanced_config || '';
    requireCondition(typeof before === 'string' && !before.includes('streams-aio-recovery-proof'));
    const after = markerConfig(before, input.nonce);
    const saved = {schema: 1, id: row.id, before, after, nonce: input.nonce};
    fs.writeFileSync(journal, JSON.stringify(saved), {flag: 'wx', mode: 0o600});
    await hosts.query().patchAndFetchById(row.id, {advanced_config: after});
    await render(await readHost(row.id));
  }
  output(JSON.stringify({status: 'PASS'}) + '\n');
  process.exit(0);
} catch {
  // Interrupted changes are described by the private journal and can be
  // reversed on the next invocation. Never forward NPM library exceptions.
  output(JSON.stringify({status: 'FAIL', code: 'DOMAIN_PROBE_REFUSED'}) + '\n');
  process.exit(1);
}
