import {readFileSync,writeFileSync,readdirSync,mkdirSync,lstatSync,copyFileSync,existsSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve,join,dirname,relative,isAbsolute} from 'node:path';
import {fileURLToPath} from 'node:url';

const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const directories=['src','public','data','roles','scripts','deploy','test','node_modules','docs'];
const excludedTests=['test/public-qa-grounding-comparison.test.mjs','test/public-qa-grounding.test.mjs','test/public-qa-stage2-workload.test.mjs'];
const selectedReports=['kr-ai-basic-governance-verification-20261006.md','kr-governance-check-contract-20261006.json','kr-governance-six-cases-final-20261006.json','kr-governance-six-cases-copy-receipt-20261006.json','kr-governance-six-cases-copied-verification-20261006.json','kr-governance-image-source-match-20261006.json','kr-governance-resource-status-20261006.json','kr-governance-verification-manifest-20261006.json','kr-governance-browser-closure-20261006.png','kr-governance-host-regression-final-r3-20261006.log','kr-governance-container-r18-20261006.log','kr-governance-final-gaps-confirmed-20261006.log','public-qa-grounding-verification-20261005.json','public-qa-grounding-and-recovery-20261005.md','first-release-dependency-audit-20261006.json','first-release-startup-confirmed-20261006.log','first-release-full-regression-20261006.log','first-release-container-20261006.log','first-release-20261006.md'];
selectedReports.push('first-release-install-regression-confirmed-20261006.log','first-release-assistance-diagnosis-20261006.log','first-release-sbom-20261006.json','first-release-startup-final-20261006.log');
selectedReports.push('finance-known-reference-fix-20261006.md','kr-governance-current-law-review-20261006.md','kr-governance-33-fix-20261006.md','kr-governance-33-ui-fix-20261006.md','memory-training-recovery-20261006.md','memory-training-recovery-20261006.json','public-qa-grounding-continuation-verification-20261006.json');
selectedReports.push('kr-supplier-reliance-fix-20261006.md','kr-supplier-reliance-ui-20261006.log','fresh-controller-supplier-independent-review-20261006.md');
selectedReports.push('memory-stability-20261006.md','memory-stability-20261006.json','memory-execution-boundary-review-20261006.md','memory-execution-boundary-final-fixed-tests-20261006.log');

function relativeWorkspacePath(value,prefix){
 if(typeof value!=='string'||isAbsolute(value)||/^[A-Za-z]:/.test(value))throw Error('Workspace-relative path required');
 const path=value.replaceAll('\\','/'),parts=path.split('/');
 if(parts.some(part=>!part||part==='.'||part==='..'||/[<>:"|?*\u0000]/.test(part))||prefix&&!path.startsWith(prefix+'/'))throw Error('Invalid workspace-relative path: '+value);
 return path;
}
function rejectSymlinks(path){
 let current=root;
 for(const part of relativeWorkspacePath(path).split('/')){
  current=join(current,part);
  try{if(lstatSync(current).isSymbolicLink())throw Error('Workspace symlink rejected: '+path);}
  catch(error){if(error.code==='ENOENT')return;throw error;}
 }
}
function verifyRecordedRelease(evidenceDirectory){
 rejectSymlinks(evidenceDirectory);
 const directory=join(root,evidenceDirectory),path=join(directory,'verification.json');
 rejectSymlinks(evidenceDirectory+'/verification.json');
 if(!existsSync(path))return null;
 const evidence=JSON.parse(readFileSync(path,'utf8'));
 if(evidence.passed!==true||evidence.requestedRounds!==10||evidence.completedRounds!==10||evidence.passedRounds!==10||evidence.rounds?.length!==10)throw Error('Ten release rounds are not verified');
 if(!evidence.sourceSnapshot?.files||hash(Buffer.from(JSON.stringify(evidence.sourceSnapshot.files)))!==evidence.sourceSnapshot.sha256)throw Error('Release source inventory invalid');
 for(const [path,digest]of Object.entries(evidence.sourceSnapshot.files)){
  const source=relativeWorkspacePath(path);rejectSymlinks(source);
  if(!existsSync(join(root,source))||!lstatSync(join(root,source)).isFile()||hash(readFileSync(join(root,source)))!==digest)throw Error('Release source changed: '+path);
 }
 for(const [index,round]of evidence.rounds.entries()){
  const counts=round.counts;
  if(round.round!==index+1||round.passed!==true||round.exitCode!==0||round.terminationConfirmed!==true||round.timedOut||round.sourceChanged||round.sourceSha256After!==evidence.sourceSnapshot.sha256||!counts||counts.tests<1||counts.tests!==counts.pass||['fail','cancelled','skipped','todo'].some(key=>counts[key]!==0))throw Error('Release round evidence invalid');
  if(round.log!==`round-${String(index+1).padStart(2,'0')}.log`)throw Error('Release round log mismatch');
  rejectSymlinks(evidenceDirectory+'/'+round.log);
  if(hash(readFileSync(join(directory,round.log)))!==round.logSha256)throw Error('Release round log mismatch');
 }
 return evidence;
}

export function packageRelease(destination,{verificationDirectory='reports/first-release-20261006'}={}){
 const version=JSON.parse(readFileSync(join(root,'package.json'),'utf8')).version;
 const semver=/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
 if(typeof version!=='string'||!semver.test(version))throw Error('Root package.json version must be valid SemVer');
 const evidenceDirectory=relativeWorkspacePath(verificationDirectory,'reports');
 const evidence=verifyRecordedRelease(evidenceDirectory);
 const output=resolve(destination),suffix=relative(root,output);
 if(!suffix||suffix.startsWith('..')||!suffix.replaceAll('\\','/').startsWith('releases/'))throw Error('Release output must be a new directory inside workspace releases/');
 relativeWorkspacePath(suffix,'releases');rejectSymlinks(suffix);
 if(existsSync(output))throw Error('Release output already exists; refusing overwrite');
 const paths=[];
 function collect(directory){
  rejectSymlinks(directory);
  for(const entry of readdirSync(join(root,directory),{withFileTypes:true})){
   const path=directory+'/'+entry.name;
   if(entry.isSymbolicLink())throw Error('Release source symlink rejected: '+path);
   if(path==='docs/user-request.ko.md'||excludedTests.includes(path)||path.split('/').includes('__pycache__')||/(?:^|\/)\.env(?:\.|$)/.test(path)||/\.(?:key|pfx|p12|sqlite\d*|db|gguf|safetensors|pt|pth|ckpt|onnx)(?:-wal|-shm)?$/i.test(path))continue;
   if(entry.isDirectory())collect(path);
   else if(entry.isFile()){
    if(/\.pem$/i.test(path)){
     const publicFixture=path.startsWith('test/fixtures/')||path.startsWith('reports/kr-governance-six-cases-evidence-20261006/')&&path.endsWith('/public-key.pem');
     if(!publicFixture||/PRIVATE KEY/.test(readFileSync(join(root,path),'utf8')))continue;
    }
    paths.push(path);
   }
  }
 }
 for(const directory of directories)collect(directory);
 paths.push('package.json','package-lock.json','Dockerfile','.dockerignore','.gitignore');
 for(const name of selectedReports)if(existsSync(join(root,'reports',name)))paths.push('reports/'+name);
 for(const directory of new Set(['reports/kr-governance-six-cases-evidence-20261006','reports/first-release-20261006',evidenceDirectory]))if(existsSync(join(root,directory)))collect(directory);
 const unique=[...new Set(paths)].sort();
 // Validate the source inventory before creating any deliverable.
 for(const path of unique)if(!lstatSync(join(root,path)).isFile())throw Error('Release source is not a regular file: '+path);
 mkdirSync(dirname(output),{recursive:true});mkdirSync(output);
 const files={};
 for(const path of unique){const target=join(output,path);mkdirSync(dirname(target),{recursive:true});copyFileSync(join(root,path),target);files[path]={sha256:hash(readFileSync(target)),bytes:lstatSync(target).size};}
 const readme=`# EvidScope ${version}\n\n한국 AI 기본법 거버넌스·감사 증거 대조의 통제된 로컬/폐쇄망 파일럿 출시본입니다.\n\n[설치 및 첫 검토 안내](docs/first-release-20261006.md) · [한국법 증거 계약](docs/kr-governance-evidence.md) · [법령 확인 범위](docs/legal-sources.md)\n\nNode 24.15.x와 고정한 런타임 의존성을 포함한 node_modules를 사용합니다. Node 실행 파일·모델 가중치·자격·개인키·DB는 포함하지 않습니다.\n\nPowerShell에서: \n\n\`\`\`powershell\n$env:EVIDSCOPE_LOCAL_HOST='::1'\nnpm start\n\`\`\`\n\n감사 화면 http://[::1]:8082. 처음 시작할 때 .local에 고유한 로컬 자격과 키를 생성합니다. 별도 터미널에도 같은 HOST/DIR/PORT_BASE 설정을 지정해 npm run demo를 실행합니다. Ctrl+C로 종료합니다.\n\n[10회 실제 검증](${evidenceDirectory}/verification.json)과 release-manifest.json에서 출시 근거 및 파일 해시를 확인하세요. 반복 검증은 npm run release:verify -- --output NEW_DIRECTORY입니다.\n\n라이선스: UNLICENSED, private. 공개 재배포나 법률 준수 인증이 아닌 통제된 파일럿 전달입니다. 포함된 npm 의존성의 LICENSE 파일은 각 node_modules 패키지에서 확인하세요.\n\n실제 기관 연동·고시 전체·장기 보존 실적·새 모델의 생성 품질 승인·원격 HA는 이 출시의 완료 범위가 아닙니다. 과거 연구 문서의 링크에는 원본 저장소에서 제공하는 자료가 포함될 수 있습니다.\n`;
 writeFileSync(join(output,'README.md'),readme);files['README.md']={sha256:hash(Buffer.from(readme)),bytes:Buffer.byteLength(readme)};
 const manifest={schemaVersion:1,product:'EvidScope',version,createdAt:new Date().toISOString(),audience:'controlled_local_pilot',externalPublicationPerformed:false,nodeRuntimeRequired:'24.15.x',bundledRuntimeDependencies:true,privateCredentialsIncluded:false,modelWeightsIncluded:false,legalComplianceCertified:false,excludedTests,excludedTestBasis:'Three training experiment test files contain 8 checks, including 6 requiring unshipped private local records. Training experiments and model promotion are outside this release.',verification:{evidenceDirectory,passed:evidence?.passed===true&&evidence?.passedRounds===10,rounds:evidence?.passedRounds||0},files};
 writeFileSync(join(output,'release-manifest.json'),JSON.stringify(manifest,null,2)+'\n');
 return {directory:output,files:Object.keys(files).length,totalBytes:Object.values(files).reduce((sum,file)=>sum+file.bytes,0),version:manifest.version,verification:manifest.verification};
}
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 try{const args=process.argv.slice(2);if(![2,4].includes(args.length)||args[0]!=='--output'||!args[1]||args.length===4&&(args[2]!=='--verification-directory'||!args[3]))throw Error('Usage: node scripts/package-release.mjs --output releases/NEW_DIRECTORY [--verification-directory reports/NEW_DIRECTORY]');console.log(JSON.stringify(packageRelease(args[1],args.length===4?{verificationDirectory:args[3]}:{}),null,2));}
 catch(error){console.error(error.message);process.exitCode=1;}
}
