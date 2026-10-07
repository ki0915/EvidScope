import {readFileSync,writeFileSync,existsSync,lstatSync} from 'node:fs';
import {createPrivateKey,createPublicKey} from 'node:crypto';
import {resolve,sep,relative,isAbsolute,dirname} from 'node:path';
import {parseArgs} from 'node:util';
import {createVaultBackup,restoreVaultBackup,createVaultRecoveryFrontier} from '../src/vault-recovery.mjs';
import {dataKeysFromEnv} from '../src/data-keys.mjs';
import {rebindRecoveryConfig} from '../src/recovery-state.mjs';

// Transparency options (positional usage is unchanged):
//  frontier ... [--transparency-config CURRENT.json] [--transparency-out FRONTIER_TRANSPARENCY.json]
//  restore  ... --transparency-config NEW_EPOCH.json [--previous-transparency-config OLD.json] [--previous-pin OLD_PIN.json]
//               [--frontier-transparency FRONTIER_TRANSPARENCY.json] [--accept-loss REASON]
// Config rebinding of an activated restoration (docs/vault-recovery.md):
//  rebind DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY CURRENT_CONFIG NEW_CONFIG --reason REASON
const restoreFlags=['transparency-config','previous-transparency-config','previous-pin','frontier-transparency','accept-loss'];
try{
 const options={...Object.fromEntries(restoreFlags.map(name=>[name,{type:'string'}])),'transparency-out':{type:'string'},reason:{type:'string'}};
 const {values,positionals}=parseArgs({allowPositionals:true,options});
 const [mode,...args]=positionals;
 const dataKeys=dataKeysFromEnv(process.env),eventKeystoreDir=process.env.EVENT_KEYSTORE_DIR?resolve(process.env.EVENT_KEYSTORE_DIR):undefined;
 const json=file=>{if(lstatSync(file).size>16*1024*1024)throw Error('Recovery input exceeds 16MiB');return JSON.parse(readFileSync(file,'utf8').replace(/^﻿/,''));};
 const noLinks=file=>{for(let current=resolve(file);;){if(existsSync(current)&&lstatSync(current).isSymbolicLink())throw Error('Recovery output symlink or junction is not allowed');const parent=dirname(current);if(parent===current)return;current=parent;}};
 const outside=(file,dir)=>{noLinks(file);noLinks(dir);const rel=relative(dir,file);if(!rel||!isAbsolute(rel)&&rel!=='..'&&!rel.startsWith('..'+sep))throw Error('Recovery pin/output must be stored outside data and backup directories');};
 const allowed=mode==='frontier'?['transparency-config','transparency-out']:mode==='restore'?restoreFlags:mode==='rebind'?['reason']:[];
 for(const [name,value] of Object.entries(values))if(value!==undefined&&!allowed.includes(name))throw Error(`--${name} is not an option of ${mode||'this command'}`);
 if(mode==='frontier'){
  if(args.length!==7)throw Error('Usage: frontier DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY ARCHIVE_ANCHOR CONFIG NEW_FRONTIER NEW_FRONTIER_ANCHOR [--transparency-config CURRENT.json] [--transparency-out FILE]');
  const [dataDir,keyFile,publicFile,archiveAnchorFile,configFile,frontierFile,pinFile]=args.map(p=>resolve(p)),companionFile=values['transparency-out']?resolve(values['transparency-out']):null;
  if(new Set([frontierFile,pinFile,companionFile].filter(Boolean)).size!==(companionFile?3:2)||[frontierFile,pinFile,companionFile].some(file=>file&&existsSync(file)))throw Error('Frontier outputs must be distinct new files; refusing overwrite');
  for(const file of [frontierFile,pinFile,companionFile].filter(Boolean))outside(file,dataDir);
  const result=await createVaultRecoveryFrontier({dataDir,privateKey:readFileSync(keyFile),publicKey:readFileSync(publicFile),...dataKeys,eventKeystoreDir,
   anchor:json(archiveAnchorFile),config:json(configFile),transparency:values['transparency-config']?json(resolve(values['transparency-config'])):undefined});
  if(companionFile&&!result.transparency)throw Error('The source vault has no transparency heads log; nothing to write to --transparency-out');
  writeFileSync(frontierFile,JSON.stringify(result.frontier,null,2)+'\n',{flag:'wx',mode:0o600});
  writeFileSync(pinFile,JSON.stringify(result.anchor,null,2)+'\n',{flag:'wx',mode:0o600});
  if(companionFile)writeFileSync(companionFile,JSON.stringify(result.transparency,null,2)+'\n',{flag:'wx',mode:0o600});
  const companion=companionFile?{frontierTransparency:{file:companionFile,headsOrigin:result.transparency.headsOrigin,headsSize:result.transparency.headsSize}}:{};
  console.log(JSON.stringify({created:true,frontierFile,independentFrontierAnchor:pinFile,frontierSha256:result.anchor.frontierSha256,freshnessIndependentlyVerified:false,...companion}));
 }else if(mode==='rebind'){
  if(args.length!==5||!values.reason?.trim())throw Error('Usage: rebind DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY CURRENT_CONFIG NEW_CONFIG --reason REASON');
  const [dataDir,keyFile,publicFile,currentFile,newFile]=args.map(p=>resolve(p)),key=createPrivateKey(readFileSync(keyFile));
  const der=value=>createPublicKey(value).export({type:'spki',format:'der'});
  if(!der(key).equals(der(readFileSync(publicFile))))throw Error('The signing key does not match the pinned public key');
  const result=rebindRecoveryConfig({dataDir,key,currentConfig:json(currentFile),config:json(newFile),reason:values.reason});
  console.log(JSON.stringify({...result,nextStep:'Replace the vault CONFIG_FILE with NEW_CONFIG and start the vault'}));
 }else{
 if(!['create','restore'].includes(mode)||!(args.length===5||mode==='restore'&&args.length===8))throw Error('Usage: create DATA_DIR BACKUP_DIR PRIVATE_KEY PINNED_PUBLIC_KEY EXTERNAL_ANCHOR | restore BACKUP_DIR NEW_DATA_DIR PRIVATE_KEY PINNED_PUBLIC_KEY EXTERNAL_ANCHOR [FRONTIER FRONTIER_ANCHOR CONFIG] [--transparency-config NEW_EPOCH.json ...]');
 const [first,second,keyFile,publicFile,anchorFile]=args.map(p=>resolve(p));
 const archive=mode==='create'?second:first;
 outside(anchorFile,archive);
 const shared={privateKey:readFileSync(keyFile),publicKey:readFileSync(publicFile),...dataKeys,eventKeystoreDir};
 if(mode==='create'){
  if(existsSync(anchorFile))throw Error('External recovery anchor already exists; refusing overwrite');
  // CONFIG_FILE (optional, as for the server) lets an enterprise-profile vault refuse a signing-key-sealed backup before its first start.
  const anchor=await createVaultBackup({dataDir:first,backupDir:second,...shared,config:process.env.CONFIG_FILE?json(resolve(process.env.CONFIG_FILE)):undefined});
  writeFileSync(anchorFile,JSON.stringify(anchor,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({created:true,backupDirectory:second,externalAnchor:anchorFile,manifestSha256:anchor.manifestSha256,privateKeyIncluded:false,dataKeyIncluded:false,eventKeystoreIncluded:false,backupEncryption:dataKeys.dataKey?'data_key_hkdf':'legacy_signing_key_derived'}));
 }else{
  const anchor=json(anchorFile),activation=args.length===8?{frontier:json(resolve(args[5])),frontierAnchor:json(resolve(args[6])),config:json(resolve(args[7]))}:{};
  if(args.length===8)outside(resolve(args[6]),archive);
  if(!values['transparency-config']&&restoreFlags.some(name=>values[name]!==undefined))throw Error('--transparency-config (the new epoch) is required with the other transparency restore options');
  const optional=(name,key)=>values[name]===undefined?{}:{[key]:json(resolve(values[name]))};
  const transparency=values['transparency-config']?{config:json(resolve(values['transparency-config'])),...optional('previous-transparency-config','previous'),
   ...optional('previous-pin','previousPin'),...optional('frontier-transparency','frontierTransparency'),...(values['accept-loss']===undefined?{}:{acceptLoss:values['accept-loss']})}:undefined;
  console.log(JSON.stringify(await restoreVaultBackup({backupDir:first,restoreDir:second,...shared,anchor,...activation,...(transparency?{transparency}:{})})));
 }
 }
}catch(error){console.error(JSON.stringify({ok:false,error:error.message}));process.exitCode=1;}
