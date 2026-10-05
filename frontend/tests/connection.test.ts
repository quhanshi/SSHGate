import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {connectedRecord,deriveOrbit,encryptedSeqs,hostKeyLabel,orbitElapsed,orbitTitle,eventNote} from '../src/connection.ts';
import {hopSpan,orbitCurve} from '../src/orbitPath.ts';
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
test('host key mismatch and rejection are distinct from an untrusted pending key',()=>{
 const key=event(1,'host_key_received','host_key',{fingerprint:'SHA256:new',key_type:'ssh-ed25519'});
 assert.equal(derive([key]).hostKey,'pending');assert.equal(hostKeyLabel(derive([key])),'尚未信任');
 const mismatch=derive([key,event(2,'connection_failed','host_key',{code:'host_key_mismatch',expected_fingerprint:'SHA256:old'})]);
 assert.equal(mismatch.hostKey,'mismatch');assert.equal(mismatch.trusted,false);assert.equal(hostKeyLabel(mismatch),'与已保存记录不符');
 assert.equal(derive([key,event(2,'connection_failed','host_key',{code:'host_key_rejected'})]).hostKey,'rejected');
 assert.equal(derive([key,event(2,'connection_failed','host_key',{code:'timeout'})]).hostKey,'incomplete');
});
test('trust source is reported only after verification',()=>{
 const o=derive([event(1,'host_key_received','host_key'),event(2,'host_key_verified','host_key',{source:'known_hosts'})]);
 assert.equal(o.hostKey,'verified');assert.equal(o.trustSource,'known_hosts');assert.match(hostKeyLabel(o),/known_hosts/);
});
test('key exchange completes and the cable seals only after the transport is encrypted',()=>{
 let o=derive([event(1,'banner_received','ssh_banner'),event(2,'algorithms_negotiated','key_exchange',{kex:'curve25519-sha256'})]);
 assert.equal(o.encrypted,false);assert.equal(o.completed.has('key_exchange'),false);
 o=derive([event(1,'algorithms_negotiated','key_exchange'),event(2,'host_key_received','host_key')]);
 assert.equal(o.encrypted,true);assert.equal(o.completed.has('key_exchange'),true);
 const retry={...event(3,'attempt_started','connecting'),attempt:2};
 assert.equal(derive([event(1,'host_key_received','host_key'),retry]).encrypted,false);
 assert.deepEqual([...encryptedSeqs([event(1,'tcp_started'),event(2,'host_key_received','host_key'),event(3,'authenticated','authentication'),retry])],[2,3]);
});
test('authentication methods keep their real order and outcome',()=>{
 const o=derive([event(1,'authentication_method_started','authentication',{method:'publickey'}),event(2,'authentication_method_failed','authentication',{method:'publickey'}),
  event(3,'authentication_method_started','authentication',{method:'publickey'}),event(4,'authentication_method_failed','authentication',{method:'publickey'}),
  event(5,'authentication_method_started','authentication',{method:'password'}),event(6,'authenticated','authentication',{method:'password'})]);
 assert.deepEqual(o.auth,[{method:'publickey',status:'failed',count:2},{method:'password',status:'ok',count:1}]);
});
test('a credential prompt before a retry does not advance the cable',()=>{
 const retry=(seq:number,name:string,stage:string)=>({...event(seq,name,stage),attempt:2});
 assert.equal(derive([retry(1,'attempt_started','connecting'),retry(2,'credentials_required','authentication')]).cable,.04);
 assert.equal(derive([retry(1,'attempt_started','connecting'),retry(2,'tcp_started','tcp'),retry(3,'authentication_started','authentication')]).cable,.95);
});
test('jump aliases come from observed jump events',()=>{
 const jump={...event(1,'connected','connected'),connection_context:{...context,role:'jump' as const,host_alias:'bastion',hop_count:2}};
 const target={...event(2,'jump_channel_started'),connection_context:{...context,hop_index:2,hop_count:2,via_host_alias:'bastion'}};
 assert.deepEqual(derive([jump,target]).jumps,['bastion']);
});
test('jump and proxy routes resolve names remotely and never tick a local DNS step',()=>{
 const hop={...context,hop_index:2,hop_count:2,via_host_alias:'bastion'};
 const jump=derive([{...event(1,'jump_channel_started'),connection_context:hop}]);
 assert.equal(jump.resolver,'jump');assert(!jump.completed.has('dns'));
 const proxy=derive([event(1,'proxy_started','proxy'),event(2,'proxy_process_started','proxy'),event(3,'banner_received','ssh_banner')]);
 assert.equal(proxy.resolver,'proxy');assert(!proxy.completed.has('dns'));assert(proxy.completed.has('tcp'));
 assert.equal(derive([event(1,'dns_started','dns')]).resolver,'local');
});
test('the connected log record carries only real summary fields',()=>{
 assert.equal(connectedRecord({...event(1,'connected','connected',{key_type:'ssh-ed25519',cipher_out:'aes128-ctr',auth_method:'publickey'}),elapsed_ms:1240}),'SSH 已连接 · 1.24s · ssh-ed25519 · aes128-ctr · publickey');
 assert.equal(connectedRecord({...event(1,'connected','connected'),elapsed_ms:80}),'SSH 已连接 · 0.08s');
});
test('cable progress starts where the path leaves the covering panel',()=>{
 const start={x:40,y:840},end={x:1000,y:150},panel={left:30,top:540,right:670,bottom:850};
 const {point,visible}=orbitCurve(start,end,panel);
 assert(visible>.3&&visible<.9);const q=point(visible);assert(!(q.x<=panel.right&&q.y>=panel.top));
 assert.equal(orbitCurve(start,end).visible,0);
 const two=hopSpan(visible,2,2);assert.equal(two.from,visible+(1-visible)/2);assert.equal(two.to,1);
 const clamped=hopSpan(0,5,2);assert.equal(clamped.h,2);assert.equal(clamped.to,1);
});
