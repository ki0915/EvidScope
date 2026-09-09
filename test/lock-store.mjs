import {DatabaseSync} from 'node:sqlite';
const db=new DatabaseSync(process.argv[2]);db.exec('BEGIN IMMEDIATE');process.send('locked');process.on('message',()=>{db.exec('ROLLBACK');db.close();process.exit(0);});
