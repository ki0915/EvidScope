import {readFileSync,statSync} from 'node:fs';
import {verifyCaseReport} from '../src/report-verifier.mjs';
try {
 const [reportPath,keyPath,checkpointPath]=process.argv.slice(2);
 if(!reportPath||!keyPath)throw Error('Usage: node scripts/verify-case-report.mjs REPORT.json SEPARATELY_TRUSTED_KEY.pem [EXTERNAL_CHECKPOINT.json]');
 if(statSync(reportPath).size>20*1024*1024)throw Error('Report exceeds 20 MiB limit');
 const result=verifyCaseReport(JSON.parse(readFileSync(reportPath,'utf8')),readFileSync(keyPath,'utf8'),{expectedCheckpoint:checkpointPath?JSON.parse(readFileSync(checkpointPath,'utf8')):undefined});
 console.log(JSON.stringify(result,null,2));
} catch(error) {console.error(error.message);process.exitCode=1;}
