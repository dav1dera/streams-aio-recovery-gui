"""Deterministic public Glances/Docker fixture; no real host or Docker access."""
import argparse,json
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit

GIB=1024**3
MIB=1024**2
CONTAINERS=[{'id':'fixture-'+str(i),'name':'fixture-worker-'+str(i),'status':'running','cpu_percent':float(18-i),'memory':{'usage':i*128*MIB,'inactive_file':16*MIB}} for i in range(1,8)]
MEMORY={'total':12*GIB,'used':7*GIB,'available':5*GIB,'free':5*GIB,'percent':58.3}
FS=[{'key':'mnt_point','mnt_point':'/','device_name':'fixture-volume','size':320*GIB,'used':150*GIB,'free':170*GIB,'percent':46.875}]
class Handler(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  path=urlsplit(self.path).path
  endpoint=path.rsplit('/',1)[-1]
  value=None
  if path=='/health': value={'status':'ok'}
  elif path.startswith('/api/4/'):
   value={'cpu':{'total':18.0,'user':12.0,'system':6.0},'load':{'min1':0.2,'min5':0.3,'min15':0.4},'mem':MEMORY,'fs':FS,'uptime':'2 days, 03:04:05','quicklook':{'cpu_name':'Isolated appearance CPU','cpu_hz_current':2400,'cpu_hz':2400,'cpu':18.0,'mem':58.3},'containers':CONTAINERS,'processlist':[{'pid':100+i,'status':'S','name':'fixture-process-'+str(i),'cpu_percent':float(i),'memory_info':{'rss':i*32*MIB}} for i in range(1,8)],'sensors':[]}.get(endpoint)
  elif path.endswith('/_ping') or path=='/_ping':
   raw=b'OK';self.send_response(200);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw);return
  elif '/containers/' in path and path.endswith('/stats'):
   value={'cpu_stats':{'cpu_usage':{'total_usage':20,'percpu_usage':[10,10]},'system_cpu_usage':200,'online_cpus':2},'precpu_stats':{'cpu_usage':{'total_usage':10},'system_cpu_usage':100},'memory_stats':{'usage':256*MIB,'limit':GIB,'stats':{'inactive_file':16*MIB}},'networks':{}}
  elif path.endswith('/containers/json'):
   value=[{'Id':'fixture','Names':['/'+n],'State':'running','Status':'Up 2 hours (healthy)'} for n in ('aiostreams','aiometadata','comet','jackett','mediaflow-proxy-light','easyproxy','stremthru','seanime','seanime-shared','streamvix','tvvoo','wud','portainer','aiomanager','headplane','nginx-proxy-manager','dnscrypt-proxy')]
  elif '/containers/' in path and path.endswith('/json'): value={'Id':'fixture','State':{'Status':'running','Running':True,'Health':{'Status':'healthy'}},'Config':{'Labels':{}},'Name':'fixture'}
  elif path.endswith('/version'): value={'ApiVersion':'1.47','Version':'fixture'}
  if value is None:
   self.send_response(404);self.end_headers();return
  raw=json.dumps(value).encode();self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
if __name__=='__main__':
 parser=argparse.ArgumentParser();parser.add_argument('--port',type=int,default=61208);options=parser.parse_args()
 ThreadingHTTPServer(('0.0.0.0',options.port),Handler).serve_forever()
