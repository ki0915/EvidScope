import {execFileSync} from 'node:child_process';
import {dirname,join} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
import {trainingStartDecision,validateHostResourceReceipt} from '../src/training-resource-guard.mjs';

const root=dirname(fileURLToPath(import.meta.url));
export function probeWindowsHostResources({execute=execFileSync,now}={}){
 const raw=execute('powershell.exe',['-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',join(root,'training-host-probe.ps1')],{encoding:'utf8',timeout:10000,maxBuffer:16384,windowsHide:true,stdio:['ignore','pipe','pipe']});
 if(Buffer.byteLength(raw)>16384)throw Error('host_resource_receipt_too_large');
 return validateHostResourceReceipt(JSON.parse(raw),{now:now??Date.now()});
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 try{const receipt=probeWindowsHostResources(),decision=trainingStartDecision(receipt);process.stdout.write(JSON.stringify({receipt,decision},null,2)+'\n');process.exitCode=decision.allowed?0:2;}
 catch{process.stdout.write(JSON.stringify({receipt:null,decision:{allowed:false,reasons:['host_resource_probe_unavailable']}},null,2)+'\n');process.exitCode=2;}
}
