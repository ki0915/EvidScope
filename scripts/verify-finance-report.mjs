import {readFileSync,statSync} from 'node:fs';
import {verifyFinanceReport} from '../src/report-verifier.mjs';
try{
 const args=process.argv.slice(2),[reportPath,keyPath,expectedReportHash]=args;
 if(args.length<2||args.length>3)throw Error('Usage: node scripts/verify-finance-report.mjs REPORT.json SEPARATELY_TRUSTED_PUBLIC_KEY.pem [EXTERNALLY_PINNED_REPORT_SHA256]');
 if(statSync(reportPath).size>20*1024*1024)throw Error('Report exceeds 20 MiB limit');
 console.log(JSON.stringify(verifyFinanceReport(JSON.parse(readFileSync(reportPath,'utf8').replace(/^\uFEFF/,'')),readFileSync(keyPath,'utf8'),{expectedReportHash}),null,2));
}catch(error){console.error(error.message);process.exitCode=1;}
