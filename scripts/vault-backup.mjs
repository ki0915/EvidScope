import {readFileSync,writeFileSync,existsSync,lstatSync} from 'node:fs';
import {resolve,sep,relative,isAbsolute,dirname} from 'node:path';
import {createVaultBackup,restoreVaultBackup,createVaultRecoveryFrontier} from '../src/vault-recovery.mjs';

const [mode,...args]=process.argv.slice(2);
try{
 const json=file=>{if(lstatSync(file).size>16*1024*1024)throw Error('Recovery input exceeds 16MiB');return JSON.parse(readFileSync(file,'utf8').replace(/^\uFEFF/,''));};
 const noLinks=file=>{for(let current=resolve(file);;){if(existsSync(current)&&lstatSync(current).isSymbolicLink())throw Error('Recovery output symlink or junction is not allowed');const parent=dirname(current);if(parent===current)return;current=parent;}};
 const outside=(file,dir)=>{noLinks(file);noLinks(dir);const rel=relative(dir,file);if(!rel||!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep))throw Error('Recovery pin/output must be stored outside data and backup directories');};
 if(mode==='frontier'){
  if(args.length!==7)throw Error('Usage: frontier DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY ARCHIVE_ANCHOR CONFIG NEW_FRONTIER NEW_FRONTIER_ANCHOR');
  const [dataDir,keyFile,publicFile,archiveAnchorFile,configFile,frontierFile,pinFile]=args.map(p=>resolve(p));
  if(frontierFile===pinFile||existsSync(frontierFile)||existsSync(pinFile))throw Error('Frontier outputs must be distinct new files; refusing overwrite');
  for(const file of [frontierFile,pinFile])outside(file,dataDir);
  const result=await createVaultRecoveryFrontier({dataDir,privateKey:readFileSync(keyFile),publicKey:readFileSync(publicFile),anchor:json(archiveAnchorFile),config:json(configFile)});
  writeFileSync(frontierFile,JSON.stringify(result.frontier,null,2)+'\n',{flag:'wx',mode:0o600});
  writeFileSync(pinFile,JSON.stringify(result.anchor,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({created:true,frontierFile,independentFrontierAnchor:pinFile,frontierSha256:result.anchor.frontierSha256,freshnessIndependentlyVerified:false}));
 }else{
 if(!['create','restore'].includes(mode)||!(args.length===5||mode==='restore'&&args.length===8))throw Error('Usage: create DATA_DIR BACKUP_DIR PRIVATE_KEY PINNED_PUBLIC_KEY EXTERNAL_ANCHOR | restore BACKUP_DIR NEW_DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY EXTERNAL_ANCHOR [FRONTIER FRONTIER_ANCHOR CONFIG]');
 const [first,second,keyFile,publicFile,anchorFile]=args.map(p=>resolve(p));
 const archive=mode==='create'?second:first;
 outside(anchorFile,archive);
 const shared={privateKey:readFileSync(keyFile),publicKey:readFileSync(publicFile)};
 if(mode==='create'){
  if(existsSync(anchorFile))throw Error('External recovery anchor already exists; refusing overwrite');
  const anchor=await createVaultBackup({dataDir:first,backupDir:second,...shared});
  writeFileSync(anchorFile,JSON.stringify(anchor,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({created:true,backupDirectory:second,externalAnchor:anchorFile,manifestSha256:anchor.manifestSha256,privateKeyIncluded:false}));
 }else{
  const anchor=json(anchorFile),activation=args.length===8?{frontier:json(resolve(args[5])),frontierAnchor:json(resolve(args[6])),config:json(resolve(args[7]))}:{};
  if(args.length===8)outside(resolve(args[6]),archive);
  console.log(JSON.stringify(await restoreVaultBackup({backupDir:first,restoreDir:second,...shared,anchor,...activation})));
 }
 }
}catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
