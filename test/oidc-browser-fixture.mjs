// Explicit, temporary synthetic IdP for browser verification. Never deploy.
import {writeFileSync,existsSync} from 'node:fs';
import {join} from 'node:path';
import {harness} from './harness.mjs';
import {startOidcProvider} from './oidc-provider.mjs';

const provider=await startOidcProvider({host:process.env.EVIDSCOPE_TEST_HOST||'127.0.0.1'});
let h,closing=false;
async function close(){if(closing)return;closing=true;await h?.close();await provider.close();process.exit(0);}
try{
 h=await harness();
 h.config.oidc={enabled:true,syntheticLocalIdp:true,issuer:provider.issuer,publicOrigin:h.audit.url,clientId:provider.clientId,clientSecret:provider.clientSecret,bindings:[{id:'browser-admin',subject:'alice',tenant:'alpha',role:'admin'},{id:'browser-reviewer',subject:'bob',tenant:'alpha',role:'reviewer'}]};
 writeFileSync(join(h.dir,'config.json'),JSON.stringify(h.config));await h.restart();
 console.log(JSON.stringify({auditUrl:h.audit.url,fixtureDir:h.dir,synthetic:true}));
 process.on('SIGINT',close);process.on('SIGTERM',close);
 process.stdin.setEncoding('utf8');process.stdin.on('data',text=>{if(text.trim()==='stop')void close();});
 // Pipe-based runners may close stdin. A fixture-local marker also permits
 // graceful cleanup without terminating unrelated node processes.
 setInterval(()=>{if(existsSync(join(h.dir,'stop-browser-fixture')))void close();},500).unref();
 setTimeout(close,15*60*1000).unref();
}catch(error){console.error(error.name);await close();}
