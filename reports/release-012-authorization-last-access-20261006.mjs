import {DatabaseSync} from 'node:sqlite';
import {resolve,join} from 'node:path';
import {writeFileSync} from 'node:fs';
const fixture=resolve('.test-runs/run-IFj0Od'),db=new DatabaseSync(join(fixture,'data/evidence.db'),{readOnly:true});
try{
 const records=db.prepare("SELECT seq,body FROM ledger WHERE tenant='alpha' ORDER BY seq DESC LIMIT 8").all().map(row=>({seq:row.seq,record:JSON.parse(row.body)}));
 const access=records.filter(row=>row.record.type==='audit_access');
 const result={readOnly:true,fixture,access};
 writeFileSync(new URL('./release-012-authorization-last-access-20261006.json',import.meta.url),JSON.stringify(result,null,2)+'\n');
 console.log(JSON.stringify(result,null,2));
}finally{db.close();}
