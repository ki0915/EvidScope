import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {trainingManifest} from '../deploy/training/render.mjs';
import {boundTrainingTemplate,trainingTemplateHash} from '../deploy/training/kubectl-adapter.mjs';

export function trainingPreparation(config){
 const job=boundTrainingTemplate(config),items=trainingManifest().items.filter(item=>item.kind!=='Job');
 for(const [name,size] of [['approved-training-data','1Gi'],['approved-training-base','20Gi'],['training-candidate-checkpoints','12Gi']])items.push({apiVersion:'v1',kind:'PersistentVolumeClaim',metadata:{name,namespace:'evidscope-training'},spec:{accessModes:['ReadWriteOnce'],resources:{requests:{storage:size}}}});
 return {schemaVersion:1,trainingRunAllowed:false,formalManifestHash:trainingTemplateHash(config),manifest:{apiVersion:'v1',kind:'List',items:[...items,job]},artifactLockBytes:JSON.stringify(config.artifactLock),artifactLockSha256:createHash('sha256').update(JSON.stringify(config.artifactLock)).digest('hex'),requiredBeforeExecution:['Load approved image by manifest digest into the selected k3d node.', 'Populate data/base PVCs in an explicit offline staging job; verify every SHA-256. The formal job mounts both read-only.', 'Run probe and resource-pilot preparation separately; never manufacture true checks.', 'Supply reviewed 300/50/100 data admission and current real probe receipts.']};
}

// Probe and pilot do not require gpuMemoryPilotPassed. They are preparation,
// not formal training. Their receipts cannot pass formal data admission.
export function preparationJob(config,{mode='probe',targetHost,allowedHost}={}){
 if(!['probe','resource-pilot'].includes(mode))throw Error('preparation_mode_invalid');
 const job=boundTrainingTemplate(config),container=job.spec.template.spec.containers[0];
 job.metadata.name=`foundation-${mode}`;job.spec.suspend=true;job.spec.activeDeadlineSeconds=mode==='probe'?120:300;
 container.command=['python','/app/training-probe.py'];container.args=['--mode',mode];
 if(mode==='probe'){
  if(!targetHost||!allowedHost||!/^\d{1,3}(\.\d{1,3}){3}$/.test(targetHost)||!/^\d{1,3}(\.\d{1,3}){3}$/.test(allowedHost))throw Error('literal_control_target_addresses_required');
  container.args.push('--denied-host',targetHost,'--allowed-host',allowedHost);
 }
 container.terminationMessagePath='/tmp/preparation-result.json';
 for(const mount of container.volumeMounts)if(mount.name==='checkpoints')mount.readOnly=true;
 job.metadata.annotations['evidscope.io/formal-template-hash']=trainingTemplateHash(config);
 job.metadata.annotations['evidscope.io/preparation-only']='true';
 return job;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){const [mode,input,output,denied,allowed]=process.argv.slice(2);const config=JSON.parse(readFileSync(input,'utf8'));const result=mode==='render'?trainingPreparation(config):preparationJob(config,{mode,targetHost:denied,allowedHost:allowed});writeFileSync(output,JSON.stringify(result,null,2)+'\n',{flag:'wx'});process.stdout.write(JSON.stringify({written:true,executed:false,trainingRunAllowed:false})+'\n');}
