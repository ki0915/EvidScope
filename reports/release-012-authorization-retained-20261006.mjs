import {readdirSync,statSync,existsSync,writeFileSync} from 'node:fs';
import {join,resolve} from 'node:path';
import {DatabaseSync} from 'node:sqlite';
const parent=resolve('.test-runs'),dirs=readdirSync(parent,{withFileTypes:true}).filter(d=>d.isDirectory()&&d.name.startsWith('run-')).map(d=>({name:d.name,path:join(parent,d.name),mtime:statSync(join(parent,d.name)).mtimeMs})).sort((a,b)=>b.mtime-a.mtime).slice(0,160),found=[];
for(const dir of dirs){const file=join(dir.path,'data','evidence.db');if(!existsSync(file))continue;let db;try{
 db=new DatabaseSync(file,{readOnly:true});const row=db.prepare("SELECT body FROM objects WHERE tenant='alpha' AND type='system' AND id='authorization-credit'").get();if(!row)continue;
 const system=JSON.parse(row.body),last=db.prepare("SELECT seq,body FROM ledger WHERE tenant='alpha' ORDER BY seq DESC LIMIT 8").all().map(row=>{const r=JSON.parse(row.body);return {seq:row.seq,type:r.type,principal:r.principal,payload:r.type==='audit'?r.payload:undefined};});
 found.push({directory:dir.name,mtime:new Date(dir.mtime).toISOString(),systemOwner:system.owner,last});
}finally{db?.close();}}
const result={readOnly:true,scanned:dirs.length,found};writeFileSync(new URL('./release-012-authorization-retained-20261006.json',import.meta.url),JSON.stringify(result,null,2)+'\n');console.log(JSON.stringify(found.slice(0,2),null,2));
