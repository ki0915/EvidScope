import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {resolve,sep} from 'node:path';
import {createVaultBackup,restoreVaultBackup} from '../src/vault-recovery.mjs';

const [mode,...args]=process.argv.slice(2);
try{
 if(!['create','restore'].includes(mode)||args.length!==5)throw Error('Usage: node scripts/vault-backup.mjs create DATA_DIR BACKUP_DIR PRIVATE_KEY PINNED_PUBLIC_KEY EXTERNAL_ANCHOR | restore BACKUP_DIR NEW_DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY EXTERNAL_ANCHOR');
 const [first,second,keyFile,publicFile,anchorFile]=args.map(p=>resolve(p));
 const archive=mode==='create'?second:first;
 if(anchorFile===archive||anchorFile.startsWith(archive+sep))throw Error('Recovery anchor must be stored outside the backup directory');
 const shared={privateKey:readFileSync(keyFile),publicKey:readFileSync(publicFile)};
 if(mode==='create'){
  if(existsSync(anchorFile))throw Error('External recovery anchor already exists; refusing overwrite');
  const anchor=await createVaultBackup({dataDir:first,backupDir:second,...shared});
  writeFileSync(anchorFile,JSON.stringify(anchor,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({created:true,backupDirectory:second,externalAnchor:anchorFile,manifestSha256:anchor.manifestSha256,privateKeyIncluded:false}));
 }else{
  const anchor=JSON.parse(readFileSync(anchorFile,'utf8').replace(/^\uFEFF/,''));
  console.log(JSON.stringify(await restoreVaultBackup({backupDir:first,restoreDir:second,...shared,anchor})));
 }
}catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
