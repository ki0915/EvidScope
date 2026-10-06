import {createHash} from 'node:crypto';
import {createReadStream,createWriteStream,existsSync,mkdirSync,readFileSync,renameSync,statSync,writeFileSync} from 'node:fs';
import {resolve,join} from 'node:path';
import {spawn} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export async function digestFile(path){const h=createHash('sha256');for await(const chunk of createReadStream(path))h.update(chunk);return h.digest('hex');}
export async function downloadTrainingBase(){
 const selected=JSON.parse(readFileSync('deploy/training/selected-model.json'));
 if(selected.repository!=='fdtn-ai/Foundation-Sec-8B-Reasoning'||!/^[a-f0-9]{40}$/.test(selected.revision))throw Error('selected_base_invalid');
 const dir=resolve('.local/training/base',selected.revision);mkdirSync(dir,{recursive:true});
 const verified=[];
 for(const file of [...selected.files].sort((a,b)=>a.size-b.size)){
  if(!/^[A-Za-z0-9_.-]+$/.test(file.path)||!Number.isSafeInteger(file.size)||file.size<=0||!/^[a-f0-9]{64}$/.test(file.sha256))throw Error('selected_file_invalid');
  const target=join(dir,file.path),partial=target+'.partial';
  if(!existsSync(target)){
   if(existsSync(partial)&&statSync(partial).size>file.size)throw Error('partial_larger_than_source');
   const url=`https://huggingface.co/${selected.repository}/resolve/${selected.revision}/${file.path}`;
   console.log(JSON.stringify({event:'downloading',file:file.path,bytes:file.size}));
   const code=await new Promise((done,reject)=>{const child=spawn('curl.exe',['--fail','--location','--retry','3','--retry-delay','2','--connect-timeout','30','--speed-limit','1024','--speed-time','90','--continue-at','-','--output',partial,'--silent','--show-error',url],{windowsHide:true,stdio:['ignore','ignore','pipe']});let err='';child.stderr.on('data',v=>{err=(err+v).slice(-1000);});child.on('error',reject);child.on('exit',c=>c===0?done(0):reject(Error(`download_failed:${file.path}:${c}:${err}`)));});
   if(code!==0)throw Error('download_failed');
   if(statSync(partial).size!==file.size||await digestFile(partial)!==file.sha256)throw Error('download_digest_mismatch:'+file.path);
   renameSync(partial,target);
  }
  if(statSync(target).size!==file.size||await digestFile(target)!==file.sha256)throw Error('local_base_digest_mismatch:'+file.path);
  verified.push({path:file.path,sha256:file.sha256,bytes:file.size});
  console.log(JSON.stringify({event:'verified',file:file.path,bytes:file.size}));
 }
 const lock={repository:selected.repository,revision:selected.revision,files:verified};
 const bytes=JSON.stringify(lock);const lockPath=join(dir,'artifact-lock.json');
 if(existsSync(lockPath)&&readFileSync(lockPath,'utf8')!==bytes)throw Error('existing_artifact_lock_mismatch');
 if(!existsSync(lockPath))writeFileSync(lockPath,bytes,{flag:'wx'});
 const receipt={schemaVersion:1,verifiedAt:new Date().toISOString(),directory:dir,repository:selected.repository,revision:selected.revision,files:verified.length,bytes:verified.reduce((sum,f)=>sum+f.bytes,0),artifactLockSha256:createHash('sha256').update(bytes).digest('hex'),trainingStarted:false};
 writeFileSync('reports/training-base-download-20260922.json',JSON.stringify(receipt,null,2)+'\n');console.log(JSON.stringify(receipt));return receipt;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){if(process.argv[2]!=='--download-selected')throw Error('explicit_selected_download_flag_required');await downloadTrainingBase();}
