import {test} from 'node:test';
import assert from 'node:assert/strict';
import {redactWithMap,redact,risk,appendLines} from '../src/utils.ts';
test('secret display redaction retains exact source offsets for copying',()=>{
 const raw='host=dev api_key=abc123 token="long secret" port=22';const r=redactWithMap(raw);
 assert.equal(r.text,'host=dev api_key=•••• token=•••• port=22');assert.equal(r.map.length,r.text.length+1);
 const start=r.text.indexOf('••••'),end=start+4;assert.equal(raw.slice(r.map[start],r.map[end]),'abc123');assert.equal(raw.slice(r.map[0],r.map.at(-1)),raw);
});
test('private key blocks are masked across lines without changing source',()=>{
 const raw='before\n-----BEGIN RSA PRIVATE KEY-----\nshort sensitive line\n-----END RSA PRIVATE KEY-----\nafter';
 assert.equal(redact(raw),'before\n••••\nafter');assert.equal(redactWithMap(raw).map.at(-1),raw.length);
});
test('Bearer keys and known prefixes are masked while ordinary paths survive',()=>{
 assert.equal(redact('Authorization: Bearer abc.def.ghi'),'Authorization: Bearer ••••');assert.equal(redact('sk-1234567890123456'),'••••');assert.equal(redact('/data/project/config.yaml 41 passed in 3.2s'),'/data/project/config.yaml 41 passed in 3.2s');
});
test('destructive command risk is reclassified from the full request',()=>{
 assert.equal(risk({command:'git reset --hard',readonly_eligible:false}),'destructive');assert.equal(risk({command:'rm -rf /tmp/work',readonly_eligible:false}),'destructive');assert.equal(risk({command:'systemctl restart app',readonly_eligible:false}),'write');assert.equal(risk({command:'cat /var/log/test.log',readonly_eligible:true}),'readonly');assert.equal(risk({command:'printf "%s" "<img src=x>"',readonly_eligible:false}),'write');
});
test('consecutive equal rows collapse only within the same request and stream',()=>{
 let id=0;const a={server:'dev',request:'r1',kind:'out' as const,raw:'repeat',at:1,animate:false};
 const r=appendLines([], [a,a,{...a,request:'r2'},a],()=>++id);assert.equal(r.lines.length,3);assert.equal(r.lines[0].count,2);assert.equal(r.lines[1].count,1);
});
test('terminal retention remains bounded and returns retired rows to terrain',()=>{
 let id=0;const rows=Array.from({length:700},(_,i)=>({server:'dev',request:'r1',kind:'out' as const,raw:String(i),at:i,animate:false}));
 const r=appendLines([],rows,()=>++id);assert.equal(r.lines.length,500);assert.equal(r.retired.length,200);assert.equal(r.lines[0].raw,'200');assert.equal(r.retired.at(-1)?.raw,'199');
});
