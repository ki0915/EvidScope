import test from 'node:test';
import assert from 'node:assert/strict';
import {readGuide,modelReference} from '../src/local-ai-pilot.mjs';
test('local pilot: model cannot choose arbitrary tools/paths and references are explicit reports',()=>{
 const guide=readGuide({function:{name:'read_product_guide',arguments:{version:'2'}}});assert.equal(guide.guide.version,'2');assert.match(guide.reference.hash,/^[a-f0-9]{64}$/);
 for(const call of [{function:{name:'shell',arguments:{version:'2'}}},{function:{name:'read_product_guide',arguments:{version:'../../config'}}},{function:{name:'read_product_guide',arguments:{version:'2',path:'.test-runs/ui/config.json'}}}])assert.throws(()=>readGuide(call));
 assert.equal(modelReference('No citation'),null);assert.equal(modelReference('{"reference":{"id":"other","version":"2"}}'),null);
 const ref=modelReference('{"answer":"text","reference":{"id":"product-guide","version":"1"}}');assert.equal(ref.version,'1');assert.equal(ref.hash,undefined,'Do not fabricate a source hash for model self-report');
});
