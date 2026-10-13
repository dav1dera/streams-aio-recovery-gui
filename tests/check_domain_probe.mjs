import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(new URL('../remote/npm-domain-probe.mjs', import.meta.url), 'utf8');
const nonce = 'a'.repeat(48), journal = '/data/.streams-aio-domain-probe.json';
const marker = before => before + `\n# streams-aio-recovery-proof\nlocation = /.well-known/streams-aio-recovery/${nonce} {\n  default_type text/plain;\n  return 200 '${nonce}';\n}\n`;
async function scenario({action='install', interrupted=false, drift=false, wrongUpstream=false, wrongWebSocket=false, brokenJournal=false, failReload=false, kind, port}={}) {
  let output='', exit, rendered=0, reloads=0;
  const host={id:7,is_deleted:0,enabled:1,certificate_id:1,domain_names:['cometnet.example.invalid'],
    forward_host:wrongUpstream?'original.example.invalid':'172.19.0.2',forward_port:port ?? (kind==='headscale'?8080:8765),forward_scheme:'http',
    allow_websocket_upgrade:!wrongWebSocket,advanced_config:'# preserve original advanced config',access_list_id:4};
  const before=host.advanced_config, files=new Map();
  if(interrupted) {
    host.advanced_config=drift?'# unrelated operator edit':marker(before);
    files.set(journal,JSON.stringify({schema:1,id:7,before,after:brokenJournal?'bad marker':marker(before),nonce}));
  }
  class Query {
    constructor(){this.id=null;this.criteria=[];}
    findById(id){this.id=id;return this;} allowGraph(){return this;} withGraphFetched(){return this;}
    where(key,value){this.criteria.push([key,value]);return this;}
    async patchAndFetchById(id,patch){assert.equal(id,host.id);Object.assign(host,patch);return host;}
    then(resolve,reject){return Promise.resolve(this.id===null
      ?(this.criteria.every(([key,value])=>host[key]===value)?[host]:[])
      :(this.id===host.id?host:undefined)).then(resolve,reject);}
  }
  const mockedFs={
    existsSync:path=>files.has(path),
    readFileSync:path=>path==='/app/package.json'?'{"version":"2.16.0"}':files.get(path),
    lstatSync:()=>({isFile:()=>true,isSymbolicLink:()=>false,nlink:1,mode:0o100600}),
    writeFileSync(path,raw,options){assert.equal(options.mode,0o600);assert.equal(options.flag,'wx');assert(!files.has(path));files.set(path,raw);},
    unlinkSync:path=>files.delete(path)
  };
  const imports={'node:fs':{default:mockedFs},'/app/models/proxy_host.js':{default:{query:()=>new Query(),defaultAllowGraph:'*',defaultExpand:[]}},
    '/app/internal/nginx.js':{default:{generateConfig:async(_kind,row)=>{assert.equal(row.id,7);rendered++;},test:async()=>{},reload:async()=>{reloads++;if(failReload)throw new Error('private URL must not appear');}}}};
  const payload={action,hostname:'cometnet.example.invalid',nonce,forward_hosts:['gluetun','172.19.0.2'],forward_port:host.forward_port};
  if(kind!==undefined)payload.kind=kind;
  const context=vm.createContext({JSON,Error,Array,Number,Promise,process:{stdout:{write:raw=>{output+=raw;}},stderr:{write(){}},
    stdin:{async *[Symbol.asyncIterator](){yield JSON.stringify(payload);}},exit:code=>{exit=code;}}});
  const cache=new Map();
  async function dependency(name){
    if(cache.has(name))return cache.get(name);assert(name in imports);
    const obj=imports[name];const module=new vm.SyntheticModule(Object.keys(obj),function(){for(const [key,value] of Object.entries(obj))this.setExport(key,value);},{context});
    cache.set(name,module);await module.link(()=>{});await module.evaluate();return module;
  }
  const module=new vm.SourceTextModule(source,{context,importModuleDynamically:dependency});
  await module.link(dependency);await module.evaluate();
  const result=JSON.parse(output.trim());assert.equal(host.access_list_id,4);
  assert(!output.includes('private URL'));assert(!output.includes('example.invalid'));
  return {host,before,files,result,exit,rendered,reloads};
}
let run=await scenario();assert.equal(run.result.status,'PASS');assert.equal(run.host.advanced_config,marker(run.before));assert(run.files.has(journal));
run=await scenario({action:'remove',interrupted:true});assert.equal(run.result.status,'PASS');assert.equal(run.host.advanced_config,run.before);assert(!run.files.has(journal));
run=await scenario({interrupted:true});assert.equal(run.result.status,'PASS');assert.equal(run.rendered,2);
for(const settings of [{action:'remove',interrupted:true,drift:true},{action:'remove',interrupted:true,brokenJournal:true},{wrongUpstream:true},{wrongWebSocket:true}]) {
  run=await scenario(settings);assert.equal(run.result.status,'FAIL');assert.equal(run.exit,1);assert.equal(run.rendered,0);
}
run=await scenario({failReload:true});assert.equal(run.result.status,'FAIL');assert(run.files.has(journal));assert.equal(run.host.advanced_config,marker(run.before));
run=await scenario({action:'remove'});assert.equal(run.result.status,'PASS');assert.equal(run.rendered,0);
run=await scenario({kind:'headscale',wrongWebSocket:true});assert.equal(run.result.status,'PASS');assert.equal(run.host.advanced_config,marker(run.before));
run=await scenario({kind:'headscale',action:'remove',interrupted:true});assert.equal(run.result.status,'PASS');assert.equal(run.host.advanced_config,run.before);assert(!run.files.has(journal));
for(const settings of [{kind:'headscale',port:8765},{kind:'other'},{port:8080}]) {
  run=await scenario(settings);assert.equal(run.result.status,'FAIL');assert.equal(run.rendered,0);
}
console.log('NPM_DOMAIN_PROBE_SEMANTIC_TESTS PASS (14 scenarios)');
