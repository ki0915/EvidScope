import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdtempSync,mkdirSync,copyFileSync,rmSync,existsSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,dirname,resolve,basename} from 'node:path';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function imageReadiness(execute=(program,args)=>execFileSync(program,args,{encoding:'utf8',timeout:10000,maxBuffer:65536,windowsHide:true,stdio:['ignore','pipe','pipe']})){
 const checks={},errors=[];
 for(const [key,program,args] of [['docker','docker',['info','--format','{{json .}}']],['gpu','nvidia-smi',['--query-gpu=uuid,memory.total','--format=csv,noheader']]]){
  try{const raw=execute(program,args);checks[key]=key==='docker'?{ready:JSON.parse(raw).OSType==='linux'}:{ready:/GPU-/.test(raw)};}catch{checks[key]={ready:false};errors.push(`${key}_unavailable`);}
 }
 return {allowed:Object.values(checks).every(value=>value.ready),checks,errors,downloadsPerformed:false};
}
export function buildTrainingImage({baseImage,tag='evidscope/qlora-training:local-candidate',output}={},execute=(program,args)=>execFileSync(program,args,{encoding:'utf8',timeout:1800000,maxBuffer:1048576,windowsHide:true,stdio:['ignore','pipe','pipe']})){
 if(!/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(baseImage||'')||!/^evidscope\/qlora-training:[a-zA-Z0-9._-]+$/.test(tag)||!output)throw Error('approved_base_digest_and_output_required');
 if(existsSync(output))throw Error('training_image_receipt_exists');
 const readiness=imageReadiness(execute);if(!readiness.allowed)throw Error('training_image_environment_not_ready');
 const context=mkdtempSync(join(tmpdir(),'evidscope-training-image-'));
 try{
  for(const file of ['deploy/training/Dockerfile','deploy/training/requirements.txt','scripts/train-foundation-lora.py','scripts/training_artifacts.py','scripts/training-paired-eval.py','scripts/training-probe.py']){const destination=join(context,file);mkdirSync(dirname(destination),{recursive:true});copyFileSync(file,destination);}
  execute('docker',['build','--pull=false','--build-arg',`TRAINING_BASE_IMAGE=${baseImage}`,'-f',join(context,'deploy/training/Dockerfile'),'-t',tag,context]);
 }finally{if(dirname(resolve(context))===resolve(tmpdir())&&basename(context).startsWith('evidscope-training-image-'))rmSync(context,{recursive:true,force:true});}
 const image=JSON.parse(execute('docker',['image','inspect',tag]))[0];
 if(!/^sha256:[a-f0-9]{64}$/.test(image?.Id||''))throw Error('training_image_digest_unavailable');
 // A local image ID is a config digest, not a registry manifest digest. Do not
 // invent repository@sha256 from it. Load into k3d; resolve RepoDigests after an
 // operator-approved local registry push before binding the runtime config.
 const receipt={schemaVersion:1,status:'built_requires_manifest_digest_and_gpu_pilot',baseImage,tag,imageId:image.Id,repoDigests:image.RepoDigests||[],recipeSha256:sha(readFileSync('deploy/training/Dockerfile')),requirementsSha256:sha(readFileSync('deploy/training/requirements.txt')),runtimeImage:null,trainingRunAllowed:false};
 const resolved=(image.RepoDigests||[]).find(value=>/^[a-zA-Z0-9./:_-]+@sha256:[a-f0-9]{64}$/.test(value));if(resolved)receipt.runtimeImage=resolved;
 writeFileSync(output,JSON.stringify(receipt,null,2)+'\n',{flag:'wx'});return receipt;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const [mode,baseImage,output]=process.argv.slice(2);try{const result=mode==='--build'?buildTrainingImage({baseImage,output}):mode==='--check-only'?imageReadiness():null;if(!result)throw Error('usage: training-image.mjs --check-only | --build approved-base@sha256:digest receipt.json');process.stdout.write(JSON.stringify(result,null,2)+'\n');if(result.allowed===false)process.exitCode=2;}catch(error){process.stdout.write(JSON.stringify({started:false,trainingRunAllowed:false,error:error.message})+'\n');process.exitCode=2;}}
