// Local, read-only documentation preview. Never serves runtime data or arbitrary paths.
import http from 'node:http';
import {readFileSync,readdirSync} from 'node:fs';
import {resolve,join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=resolve(dirname(fileURLToPath(import.meta.url)),'..'),port=Number(process.env.DOCS_PORT||9097);
if(!Number.isSafeInteger(port)||port<1024||port>65535)throw Error('Invalid DOCS_PORT');
const files=new Map([['/',join(root,'docs/viewer.html')],['/docs/viewer.html',join(root,'docs/viewer.html')],['/output/pdf/evidscope-design-handbook.pdf',join(root,'output/pdf/evidscope-design-handbook.pdf')]]);
for(const name of readdirSync(join(root,'docs')))if(name.endsWith('.md')&&name!=='user-request.ko.md')files.set('/docs/'+name,join(root,'docs',name));
for(const name of ['system-architecture.svg','document-cover.svg','architecture-cover.svg','development-cover.svg'])files.set('/docs/assets/'+name,join(root,'docs/assets',name));
for(const name of ['service-improvement-stage1.md','kubernetes-runtime-20260908.md'])files.set('/reports/'+name,join(root,'reports',name));
http.createServer((req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');
 if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);return res.end();}
 let path;try{path=decodeURIComponent(new URL(req.url,'http://localhost').pathname);}catch{res.writeHead(400);return res.end();}
 if(path==='/'){res.writeHead(302,{Location:'/docs/viewer.html'});return res.end();}
 const file=files.get(path);if(!file){res.writeHead(404);return res.end('Document not found');}
 try{const body=readFileSync(file),type=file.endsWith('.html')?'text/html; charset=utf-8':file.endsWith('.svg')?'image/svg+xml':file.endsWith('.pdf')?'application/pdf':'text/plain; charset=utf-8';res.writeHead(200,{'Content-Type':type,'Content-Length':body.length});res.end(req.method==='HEAD'?undefined:body);}catch{res.writeHead(404);res.end('Document unavailable');}
}).listen(port,'127.0.0.1',()=>console.log(`EvidScope documentation: http://127.0.0.1:${port}/docs/viewer.html`));
