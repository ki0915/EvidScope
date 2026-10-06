import {closeSync,constants,fstatSync,lstatSync,openSync,readSync} from 'node:fs';

// Read through one descriptor and never allocate or consume more than maxBytes+1.
// O_NOFOLLOW closes the POSIX symlink race; lstat keeps the same fail-closed
// behavior where that flag is unavailable. The descriptor fixes the opened file
// even if the path is replaced after open.
export function readBoundedRegularFile(path,maxBytes,{afterLstat}={}){
 if(!Number.isSafeInteger(maxBytes)||maxBytes<1)throw Error('Invalid bounded file limit');
 const initial=lstatSync(path);if(initial.isSymbolicLink()||!initial.isFile())throw Error('Document path is not a regular file');
 if(typeof afterLstat==='function')afterLstat();
 const descriptor=openSync(path,constants.O_RDONLY|(constants.O_NOFOLLOW||0));
 try{
  const current=fstatSync(descriptor);if(!current.isFile())throw Error('Document path is not a regular file');
  const bytes=Buffer.allocUnsafe(maxBytes+1);let offset=0;
  while(offset<bytes.length){const count=readSync(descriptor,bytes,offset,bytes.length-offset,null);if(count===0)break;offset+=count;}
  if(offset>maxBytes)throw Error('Document file size limit exceeded');
  return bytes.subarray(0,offset);
 }finally{closeSync(descriptor);}
}
