import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const source = fs.readFileSync(new URL('../remote/npm-route-probe.mjs', import.meta.url), 'utf8');
const nonce = 'a'.repeat(48), journal = '/data/.streams-aio-route-probe.json';
const marker = before => before + `\n# streams-aio-recovery-route-proof\nlocation = /.well-known/streams-aio-recovery/${nonce} {\n  auth_basic off;\n  auth_request off;\n  allow all;\n  default_type text/plain;\n  return 200 '${nonce}';\n}\n`;
const routing = row => ({domain_names: row.domain_names, forward_host: row.forward_host,
  forward_port: Number(row.forward_port), forward_scheme: row.forward_scheme,
  locations: row.locations || [], advanced_config: row.advanced_config || ''});
async function scenario({action='install',interrupted=false,partial=false,drift=false,
    wrongRoute=false,wrongWebSocket=false,duplicate=false,disabledComet=false,
    disabledOther=false,httpOther=false,badJournal=false,failReload=false}={}) {
  let output='',exit,rendered=0,reloads=0,patches=0;
  const hosts=[{id:7,is_deleted:0,enabled:disabledComet?0:1,certificate_id:1,
    domain_names:['cometnet.example.invalid'],forward_host:'192.0.2.29',forward_port:8765,
    forward_scheme:'http',locations:[],allow_websocket_upgrade:!wrongWebSocket,
    advanced_config:'# comet preserved',access_list_id:5},
    {id:9,is_deleted:0,enabled:disabledOther?0:1,certificate_id:httpOther?0:1,
    domain_names:['secrets.example.invalid','second.example.invalid'],forward_host:'192.0.2.30',forward_port:80,
    forward_scheme:'http',locations:[{path:'/api',forward_host:'192.0.2.30',forward_port:80,forward_scheme:'http'}],
    advanced_config:'# infisical preserved',access_list_id:6},
    {id:12,is_deleted:0,enabled:1,certificate_id:1,
    domain_names:[duplicate?'secrets.example.invalid':'external.example.invalid'],
    forward_host:'external-upstream.example.invalid',forward_port:443,forward_scheme:'https',locations:[],
    advanced_config:'# external untouched',access_list_id:7}];
  const before=hosts.map(row=>row.advanced_config),files=new Map();
  const payload={action,nonce,cometnet_id:7,cometnet_hostname:'cometnet.example.invalid',
    routes:hosts.slice(0,2).map(row=>({id:row.id,routing:routing(row)}))};
  if(wrongRoute)payload.routes[1].routing={...payload.routes[1].routing,forward_host:'old.example.invalid'};
  if(interrupted) {
    files.set(journal,JSON.stringify({schema:1,nonce,rows:hosts.slice(0,2).map((row,index)=>
      ({id:row.id,before:before[index],after:badJournal?'bad':marker(before[index])}))}));
    hosts[0].advanced_config=drift?'operator changed':marker(before[0]);
    hosts[1].advanced_config=partial?before[1]:marker(before[1]);
  }
  class Query {
    constructor(){this.id=null;this.criteria=[];}
    findById(id){this.id=id;return this;} allowGraph(){return this;} withGraphFetched(){return this;}
    where(key,value){this.criteria.push([key,value]);return this;}
    async patchAndFetchById(id,patch){const row=hosts.find(item=>item.id===id);assert(row);Object.assign(row,patch);patches++;return row;}
    then(resolve,reject){return Promise.resolve(this.id===null
      ?hosts.filter(row=>this.criteria.every(([key,value])=>row[key]===value))
      :hosts.find(row=>row.id===this.id)).then(resolve,reject);}
  }
  const mockedFs={existsSync:path=>files.has(path),
    readFileSync:path=>path==='/app/package.json'?'{"version":"2.16.0"}':files.get(path),
    lstatSync:()=>({isFile:()=>true,isSymbolicLink:()=>false,nlink:1,uid:0,mode:0o100600}),
    writeFileSync(path,raw,options){assert.equal(options.mode,0o600);assert.equal(options.flag,'wx');assert(!files.has(path));files.set(path,raw);},
    unlinkSync:path=>files.delete(path)};
  const imports={'node:fs':{default:mockedFs},'/app/models/proxy_host.js':{default:{query:()=>new Query(),defaultAllowGraph:'*',defaultExpand:[]}},
    '/app/internal/nginx.js':{default:{generateConfig:async(_kind,row)=>{assert([7,9].includes(row.id));rendered++;},
      test:async()=>{},reload:async()=>{reloads++;if(failReload)throw new Error('private-domain.invalid');}}}};
  const context=vm.createContext({JSON,Error,Array,Number,Promise,Set,Object,process:{stdout:{write:raw=>{output+=raw;}},stderr:{write(){}},
    stdin:{async *[Symbol.asyncIterator](){yield JSON.stringify(payload);}},exit:code=>{exit=code;}}});
  const cache=new Map();
  async function dependency(name){
    if(cache.has(name))return cache.get(name);assert(name in imports);
    const obj=imports[name],module=new vm.SyntheticModule(Object.keys(obj),function(){for(const [key,value] of Object.entries(obj))this.setExport(key,value);},{context});
    cache.set(name,module);await module.link(()=>{});await module.evaluate();return module;
  }
  const module=new vm.SourceTextModule(source,{context,importModuleDynamically:dependency});
  await module.link(dependency);await module.evaluate();
  const result=JSON.parse(output.trim());
  assert.equal(hosts[2].advanced_config,before[2]);assert.equal(hosts[0].access_list_id,5);assert.equal(hosts[1].access_list_id,6);
  assert(!output.includes('private-domain.invalid'));
  if(result.status==='FAIL')assert(!output.includes('example.invalid'));
  return {hosts,before,files,result,exit,rendered,reloads,patches};
}
let run=await scenario();assert.equal(run.result.status,'PASS');assert.equal(run.result.hosts,2);
assert.equal(run.result.probes.length,3);assert.equal(run.patches,2);assert.equal(run.reloads,1);
assert.equal(run.hosts[0].advanced_config,marker(run.before[0]));assert.equal(run.hosts[1].advanced_config,marker(run.before[1]));
for(const partial of [false,true]) {
  run=await scenario({action:'remove',interrupted:true,partial});assert.equal(run.result.status,'PASS');
  assert.equal(run.hosts[0].advanced_config,run.before[0]);assert.equal(run.hosts[1].advanced_config,run.before[1]);
  assert(!run.files.has(journal));assert.equal(run.reloads,1);
}
for(const options of [{wrongRoute:true},{wrongWebSocket:true},{duplicate:true},{disabledComet:true},
  {action:'remove',interrupted:true,drift:true},{action:'remove',interrupted:true,badJournal:true}]) {
  run=await scenario(options);assert.equal(run.result.status,'FAIL');assert.equal(run.patches,0);assert.equal(run.rendered,0);
}
for(const options of [{disabledOther:true},{httpOther:true}]) {
  run=await scenario(options);assert.equal(run.result.status,'PASS');assert.equal(run.result.hosts,1);
  assert.equal(run.result.probes.length,1);assert.equal(run.hosts[1].advanced_config,run.before[1]);
}
run=await scenario({failReload:true});assert.equal(run.result.status,'FAIL');assert(run.files.has(journal));
assert.equal(run.hosts[0].advanced_config,marker(run.before[0]));
run=await scenario({action:'remove'});assert.equal(run.result.status,'PASS');assert.equal(run.rendered,0);
console.log('NPM_ROUTE_PROBE_SEMANTIC_TESTS PASS (13 scenarios)');
