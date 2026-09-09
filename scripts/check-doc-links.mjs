import {readFileSync,existsSync,readdirSync} from 'node:fs';
import {resolve,dirname,join} from 'node:path';
const files=['README.md',...readdirSync('docs').filter(n=>n.endsWith('.md')&&n!=='user-request.ko.md').map(n=>join('docs',n))];
const missing=[];let links=0;
for(const file of files){
 const text=readFileSync(file,'utf8').replace(/```[\s\S]*?```/g,'');
 for(const match of text.matchAll(/\[[^\]]*\]\(([^)]+)\)/g)){
  const target=match[1].trim().replace(/^<|>$/g,'').split('#')[0];
  if(!target||/^[a-z]+:/i.test(target))continue;
  links++;if(!existsSync(resolve(dirname(file),decodeURIComponent(target))))missing.push({file,target});
 }
}
console.log(JSON.stringify({files:files.length,relativeLinks:links,missing},null,2));
if(missing.length)process.exitCode=1;
