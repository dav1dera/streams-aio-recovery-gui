// Called exclusively by npm-dr.py after fresh-target/mount/image validation.
// Uses the pinned NPM 2.16.0 implementation, not an alternate ACME client.
import fs from 'node:fs';
import tls from 'node:tls';
import https from 'node:https';
import { X509Certificate, createPrivateKey, createPublicKey } from 'node:crypto';
const output = process.stdout.write.bind(process.stdout);
process.stdout.write = () => true;
process.stderr.write = () => true;
function requireCondition(ok, code) { if (!ok) throw new Error(code); }
const sameDomains = (a,b) => JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
function validPair(id, domains) {
  try {
    const root = `/etc/letsencrypt/live/npm-${id}`;
    const cert = new X509Certificate(fs.readFileSync(`${root}/fullchain.pem`));
    const key = createPrivateKey(fs.readFileSync(`${root}/privkey.pem`));
    const sameKey = cert.publicKey.export({type:'spki',format:'der'}).equals(createPublicKey(key).export({type:'spki',format:'der'}));
    const names = (cert.subjectAltName || '').split(/,\s*/).filter(x => x.startsWith('DNS:')).map(x=>x.slice(4));
    return sameKey && sameDomains(names,domains) && Date.parse(cert.validTo)>Date.now()+86400000;
  } catch { return false; }
}
function probeName(domain) { return domain.startsWith('*.') ? 'dr-probe.'+domain.slice(2) : domain; }
async function checkTls(name) {
  await new Promise((resolve,reject) => {
    const socket=tls.connect({host:'127.0.0.1',port:443,servername:name,rejectUnauthorized:true},()=>{socket.end();resolve();});
    socket.setTimeout(15000,()=>socket.destroy(new Error('TLS_TIMEOUT')));
    socket.on('error',reject);
  });
}
async function checkHttps(name) {
  await new Promise((resolve,reject)=>{
    const request=https.get({hostname:'127.0.0.1',port:443,servername:name,path:'/',headers:{Host:name},rejectUnauthorized:true},response=>{
      response.resume();
      if(response.statusCode>=200 && response.statusCode<500)resolve();else reject(new Error('HTTPS_UPSTREAM_NOT_READY'));
    });
    request.setTimeout(15000,()=>request.destroy(new Error('HTTPS_TIMEOUT')));request.on('error',reject);
  });
}
let recoveryHosts=[];
let internalNginx;
try {
  let raw='';for await (const chunk of process.stdin)raw+=chunk;
  const input=JSON.parse(raw);const plan=input.plan;const oldId=plan.certificate.id;
  requireCondition(['reissue','verify'].includes(input.action),'INVALID_ACTION');
  requireCondition(JSON.parse(fs.readFileSync('/app/package.json')).version==='2.16.0','NPM_VERSION_MISMATCH');
  requireCondition(fs.existsSync('/data/database.sqlite') && fs.existsSync('/data/keys.json'),'INITIALIZED_REPLACEMENT_NPM_REQUIRED');
  const {default: certificates}=await import('/app/models/certificate.js');
  const {default: users}=await import('/app/models/user.js');
  const {default: internalCertificate}=await import('/app/internal/certificate.js');
  ({default:internalNginx}=await import('/app/internal/nginx.js'));
  const models={};for(const name of ['proxy_host','redirection_host','dead_host','stream'])models[name]=(await import(`/app/models/${name}.js`)).default;
  const domains=plan.certificate.domain_names;
  requireCondition(domains.length===1 && domains[0].startsWith('*.'),'SINGLE_WILDCARD_REQUIRED');
  let certificate=await certificates.query().findById(plan.current_certificate_id || oldId);
  if(!certificate && input.action==='reissue') {
    const matching=(await certificates.query().where('provider','letsencrypt')).filter(row=>sameDomains(row.domain_names,domains));
    requireCondition(matching.length<=1,'AMBIGUOUS_CERTIFICATE');
    certificate=matching[0];
    if(!certificate) {
      certificate=await certificates.query().insertAndFetch({provider:'letsencrypt',owner_user_id:plan.certificate.owner_user_id,nice_name:domains.join(', '),domain_names:domains,meta:plan.certificate.meta,is_deleted:true});
    }
  }
  requireCondition(certificate && certificate.provider==='letsencrypt' && sameDomains(certificate.domain_names,domains),'CERTIFICATE_DEFINITION_DRIFT');
  requireCondition(certificate.meta.dns_provider==='cloudflare' && certificate.meta.dns_challenge===true,'DNS_CHALLENGE_CONFIG_DRIFT');
  const owner=await users.query().findById(certificate.owner_user_id);
  requireCondition(owner && !owner.is_deleted && !owner.is_disabled && owner.email===plan.owner_email,'CERTIFICATE_OWNER_DRIFT');
  for(const [table,rows] of Object.entries(plan.hosts)) {
    requireCondition(table in models,'INVALID_HOST_TABLE');
    for(const saved of rows) {
      const row=await models[table].query().findById(saved.id);
      requireCondition(row && !row.is_deleted && [oldId,certificate.id].includes(row.certificate_id),'PROXY_ASSOCIATION_DRIFT');
      if(input.action==='verify' || plan.phase==='complete')requireCondition(row.certificate_id===certificate.id && Boolean(row.enabled)===Boolean(saved.enabled),'PROXY_RESTORE_INCOMPLETE');
      else requireCondition(!row.enabled || Boolean(row.enabled)===Boolean(saved.enabled),'PROXY_NOT_QUARANTINED');
      recoveryHosts.push({table,model:models[table],saved});
    }
  }
  if(input.action==='reissue') {
    requireCondition(typeof input.cloudflare_token==='string' && /^[A-Za-z0-9_-]+$/.test(input.cloudflare_token),'CANONICAL_TOKEN_REQUIRED');
    certificate.meta={...certificate.meta,dns_provider_credentials:`dns_cloudflare_api_token = ${input.cloudflare_token}\n`};
    // The restored row remains quarantined so NPM's timer cannot renew it
    // before issuance. DNS-01 does not require the proxy hosts to be enabled.
    if(!validPair(certificate.id,domains))await internalCertificate.requestLetsEncryptSslWithDnsChallenge(certificate,owner.email);
    requireCondition(validPair(certificate.id,domains),'ISSUED_CERTIFICATE_INVALID');
    const cert=new X509Certificate(fs.readFileSync(`/etc/letsencrypt/live/npm-${certificate.id}/fullchain.pem`));
    await certificates.query().patchAndFetchById(certificate.id,{meta:certificate.meta,is_deleted:false,expires_on:new Date(cert.validTo).toISOString().replace('T',' ').slice(0,19)});
    for(const item of recoveryHosts)await item.model.query().patchAndFetchById(item.saved.id,{certificate_id:certificate.id});
    // Basic-auth files are generated data too; their definitions live in SQLite.
    const {default: accessLists}=await import('/app/models/access_list.js');
    const {default: internalAccessList}=await import('/app/internal/access-list.js');
    const dbOwner=fs.statSync('/data/database.sqlite');
    const uid=Number(process.env.PUID || dbOwner.uid),gid=Number(process.env.PGID || dbOwner.gid);
    requireCondition(Number.isInteger(uid) && uid>=0 && Number.isInteger(gid) && gid>=0,'NPM_RUNTIME_OWNER_REQUIRED');
    fs.mkdirSync('/data/access',{recursive:true,mode:0o750});fs.chownSync('/data/access',uid,gid);fs.chmodSync('/data/access',0o750);
    for(const list of await accessLists.query().withGraphFetched('[items,clients]')) {
      if(list.is_deleted)continue;
      await internalAccessList.build(list);
      const path=internalAccessList.getFilename(list);fs.chownSync(path,uid,gid);fs.chmodSync(path,0o640);
    }
    // Rebuild all active proxy configuration, including hosts without this
    // certificate. Old /data/nginx files are disposable and were not restored.
    // Quarantined rows use their recorded enabled state; other rows keep theirs.
    for(const [table,model] of Object.entries(models)) {
      const restored=new Map((plan.hosts[table] || []).map(row=>[row.id,row]));
      const rows=await model.query().allowGraph(model.defaultAllowGraph).withGraphFetched(`[${model.defaultExpand.join(', ')}]`);
      for(const row of rows) {
        const enabled=restored.has(row.id)?restored.get(row.id).enabled:row.enabled;
        if(row.is_deleted || !enabled)continue;
        // NPM Liquid templates gate the entire server block on enabled.
        // Render the restored state without releasing DB quarantine yet.
        await internalNginx.generateConfig(table,{...row,enabled:Boolean(enabled)});
      }
    }
    await internalNginx.test();await internalNginx.reload();
    for(const item of recoveryHosts)await item.model.query().patchAndFetchById(item.saved.id,{enabled:Boolean(item.saved.enabled)});
  }
  requireCondition(validPair(certificate.id,domains),'CERTIFICATE_OR_KEY_MISSING');
  await internalNginx.test();
  let checked=0;
  for(const item of recoveryHosts) {
    if(!item.saved.enabled || item.table==='stream')continue;
    const row=await item.model.query().findById(item.saved.id);
    requireCondition(row.certificate_id===certificate.id && row.enabled,'ASSOCIATION_NOT_RESTORED');
    for(const domain of row.domain_names) {
      const name=probeName(domain);await checkTls(name);checked++;
      if(input.action==='verify')await checkHttps(name);
    }
  }
  requireCondition(checked>0,'NO_HTTPS_HOST_CHECKED');
  output(JSON.stringify({status:'PASS',certificate_id:certificate.id,CERTIFICATE:'PASS',ASSOCIATIONS:'PASS',NGINX:'PASS',TLS:'PASS',...(input.action==='verify'?{HTTPS:'PASS'}:{})})+'\n');
  process.exit(0);
} catch {
  // Do not log exceptions: library error strings may include domains or tokens.
  output(JSON.stringify({status:'FAIL',code:'RECOVERY_CHECK_FAILED'})+'\n');process.exit(1);
}
