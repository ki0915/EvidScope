import {readFileSync,statSync} from 'node:fs';
import {parseArgs} from 'node:util';
import {verifyCaseReport} from '../src/report-verifier.mjs';
import {transparencyOptions,transparencyFlags} from './transparency-flags.mjs';
try {
 const {values,positionals}=parseArgs({allowPositionals:true,options:transparencyFlags});
 const [reportPath,keyPath,checkpointPath]=positionals;
 if(!reportPath||!keyPath||positionals.length>3)throw Error('Usage: node scripts/verify-case-report.mjs REPORT.json SEPARATELY_TRUSTED_KEY.pem [EXTERNAL_CHECKPOINT.json] [--witness VKEY]... [--quorum N]'
  +' [--origin-base BASE] [--max-staleness SECONDS] [--require-transparency] [--require-tenant-witness]');
 if(statSync(reportPath).size>20*1024*1024)throw Error('Report exceeds 20 MiB limit');
 const report=JSON.parse(readFileSync(reportPath,'utf8')),transparency=transparencyOptions(values,report?.transparency!==undefined);
 const result=verifyCaseReport(report,readFileSync(keyPath,'utf8'),{expectedCheckpoint:checkpointPath?JSON.parse(readFileSync(checkpointPath,'utf8')):undefined,...(transparency?{transparency}:{})});
 console.log(JSON.stringify(result,null,2));
} catch(error) {console.error(error.message);process.exitCode=1;}
