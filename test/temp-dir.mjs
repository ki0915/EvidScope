import {after} from 'node:test';
import {mkdtempSync,rmSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join,relative,isAbsolute} from 'node:path';

// os.tmpdir() fixtures hold SQLite evidence and key-derived ciphertext. They are removed after every test of the
// importing file has finished, pass or fail; running after the tests' own close hooks keeps Windows from refusing to
// delete still-open databases. EVIDSCOPE_KEEP_TEST_RUNS=1 keeps them for diagnosis.
const directories=[];
after(()=>{
 if(process.env.EVIDSCOPE_KEEP_TEST_RUNS==='1')return;
 for(const directory of directories.splice(0)){
  try{rmSync(directory,{recursive:true,force:true,maxRetries:3});}
  catch(error){process.emitWarning(`Test fixture not removed: ${directory} (${error.code||error.message})`);}
 }
});

export function removeAfterTests(directory){
 const inside=relative(tmpdir(),directory);
 if(!inside||inside.startsWith('..')||isAbsolute(inside))throw Error(`Refusing to schedule removal outside ${tmpdir()}: ${directory}`);
 directories.push(directory);return directory;
}
export const tempDir=prefix=>removeAfterTests(mkdtempSync(join(tmpdir(),prefix)));
