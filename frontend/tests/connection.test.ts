import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {deriveOrbit,orbitElapsed,orbitTitle,eventNote} from '../src/connection.ts';
import type {ConnectionEvent} from '../src/connection.ts';
import type {RequestDetail,RequestSummary} from '../src/types.ts';
import {fingerprintArt} from '../src/fingerprint.ts';

const r={request_id:'r1',server_id:'dev',status:'running'} as RequestSummary;
const context={host_alias:'dev',hostname:'dev.fixture',port:22,role:'target' as const,hop_index:1,hop_count:1};
const event=(seq:number,name:string,stage='tcp',data:ConnectionEvent['data']={}):ConnectionEvent=>({seq,event:name,stage,attempt:1,at:'2026-10-04T00:00:00.000Z',elapsed_ms:250,hop_elapsed_ms:250,connection_context:context,data});
const derive=(events:ConnectionEvent[],request=r)=>deriveOrbit(request,{connection_events:events} as RequestDetail)!;
test('SSH SHA256 star map matches independent OpenSSH randomart output',()=>{
 const fixture=JSON.parse(readFileSync(new URL('./fixtures/fingerprint.json',import.meta.url),'utf8'));
 const art=fingerprintArt(fixture.fingerprint)!;assert.deepEqual(art.rows,fixture.rows);
 assert.equal(art.visits.length,9);assert(art.rows.every(row=>row.length===17));
});
test('unsupported or invalid fingerprints never invent a constellation',()=>{
 for(const value of ['', 'MD5:11:22', 'SHA256:fixture-only', 'SHA256:'+'A'.repeat(42), 'SHA256:'+'A'.repeat(44)])assert.equal(fingerprintArt(value),null);
});
test('repeated out-of-order snapshots are deduplicated by seq',()=>{
 const a=event(1,'tcp_started'),b=event(2,'tcp_connected');const o=derive([b,a,b]);
 assert.deepEqual(o.events.map(e=>e.seq),[1,2]);assert.equal(o.last.event,'tcp_connected');assert.equal(o.outcome,'active');
});
test('elapsed time changes without advancing a stalled connection stage',()=>{
 const o=derive([event(1,'tcp_started')]);assert.equal(orbitElapsed(o,Date.parse(o.last.at)+30000,true),30250);
 assert.equal(o.cable,.44);assert.equal(o.stage,'tcp');assert.equal(o.outcome,'active');
 assert.equal(orbitElapsed(o,Date.parse(o.last.at)+30000,false),250);
});
test('receiving a key does not imply trust; retries discard old key and trust',()=>{
 const a=event(1,'host_key_received','host_key',{fingerprint:'SHA256:old'}),b=event(2,'host_key_verified','host_key');
 assert.equal(derive([a]).trusted,false);assert.equal(derive([a,b]).trusted,true);
 const c={...event(3,'attempt_started','connecting'),attempt:2},o=derive([a,b,c]);
 assert.equal(o.metadata.fingerprint,undefined);assert.equal(o.trusted,false);assert.equal(o.attempt,2);assert.equal(o.completed.size,0);
});
test('a completed jump host never marks the target connected or leaks its fingerprint',()=>{
 const a={...event(1,'connected','connected',{fingerprint:'SHA256:jump'}),connection_context:{...context,role:'jump' as const,hop_count:2}};
 let o=derive([a]);assert.equal(o.outcome,'active');assert.equal(o.waitingForTarget,true);assert.match(orbitTitle(o),/下一跳/);
 const b={...event(2,'jump_channel_started'),connection_context:{...context,hop_index:2,hop_count:2}};
 o=derive([a,b]);assert.equal(o.metadata.fingerprint,undefined);assert.equal(o.trusted,false);assert.equal(o.completed.has('dns'),false);
});
test('reusing a connection skips handshake stages and freezes elapsed time',()=>{
 const o=derive([event(1,'connection_reused','connected',{cipher_out:'aes128-ctr'})]);
 assert.equal(o.outcome,'reused');assert.equal(o.trusted,true);assert.equal(o.completed.size,0);assert.equal(orbitElapsed(o,Date.now(),true),250);
});
test('candidate-address and authentication-method failures remain nonterminal',()=>{
 for(const name of ['tcp_address_failed','authentication_method_failed','authentication_retry'])assert.equal(derive([event(1,name,'authentication',{code:'timeout'})]).outcome,'active');
});
test('terminal failures keep their actual phase and error reason',()=>{
 const o=derive([event(1,'algorithms_negotiated','key_exchange'),event(2,'connection_failed','host_key',{code:'host_key_mismatch'})]);
 assert.equal(o.outcome,'failed');assert.equal(o.stage,'host_key');assert.equal(o.trusted,false);assert.equal(orbitTitle(o),'主机指纹不符');assert.equal(orbitElapsed(o,Date.now(),true),250);
});
test('terminated incomplete traces do not remain active or become successful',()=>{
 assert.equal(derive([event(1,'tcp_started')],{...r,status:'terminated'}).outcome,'cancelled');
 assert.equal(derive([event(1,'tcp_started')],{...r,status:'timed_out'}).code,'timeout');
});
test('a newer finished snapshot waits for its missing detail events instead of inventing failure',()=>{
 const o=derive([event(1,'tcp_started')],{...r,status:'succeeded',connection_event_seq:9});
 assert.equal(o.outcome,'active');assert.equal(o.stage,'tcp');
});
test('a failed post-SSH diagnostic preserves the successful SSH outcome',()=>{
 const o=derive([event(1,'connected','connected')],{...r,status:'failed'});assert.equal(o.outcome,'connected');assert.equal(o.request.status,'failed');
});
test('display metadata is allowlisted even when future events gain sensitive fields',()=>{
 const note=eventNote(event(1,'authentication_method_started','authentication',{method:'password',secret:'DO_NOT_DISPLAY',password:'DO_NOT_DISPLAY'}));
 assert.equal(note,'method=password');
});
