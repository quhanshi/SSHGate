import type {RequestDetail,RequestSummary} from './types';

export interface ConnectionContext {
 host_alias:string; hostname:string; port:number; role:'jump'|'target';
 hop_index:number; hop_count:number; via_host_alias?:string|null;
}
export interface ConnectionEvent {
 seq:number; event:string; stage:string; attempt:number; at:string;
 elapsed_ms:number; hop_elapsed_ms:number; connection_context:ConnectionContext;
 data:Record<string,string|number|boolean|null>;
}
export const orbitStages=['dns','tcp','ssh_banner','key_exchange','host_key','authentication','connected'] as const;
export type OrbitStage=typeof orbitStages[number];
export const stageLabels:Record<OrbitStage,string>={dns:'DNS 解析',tcp:'TCP 连接',ssh_banner:'SSH 握手',key_exchange:'密钥交换',host_key:'主机核验',authentication:'身份认证',connected:'已连接'};
export const failureLabels:Record<string,string>={dns_failed:'地址解析失败',connection_refused:'连接被拒绝',timeout:'连接超时',connection_lost:'连接中断',algorithm_mismatch:'算法无交集',protocol_mismatch:'SSH 版本不兼容',host_key_mismatch:'主机指纹不符',host_key_rejected:'未信任主机指纹',authentication_failed:'身份认证失败',proxy_failed:'代理连接失败',ssh_error:'SSH 握手失败',connection_error:'连接失败',cancelled:'连接已取消'};
const eventLabels:Record<string,string>={
 connection_started:'开始连接',connection_reused:'复用已认证连接',attempt_started:'开始本次尝试',credentials_required:'等待本地凭据',saved_credential_selected:'选用已保存凭据',
 dns_started:'解析主机地址',dns_resolved:'地址解析完成',tcp_started:'建立 TCP 连接',tcp_connected:'TCP 连接已建立',tcp_address_failed:'此地址连接失败，继续尝试',
 jump_channel_started:'打开跳板通道',jump_channel_opened:'跳板通道已打开',proxy_started:'启动本地代理',proxy_process_started:'代理进程已启动',
 ssh_handshake_started:'等待 SSH 版本',banner_received:'收到服务端版本',key_exchange_started:'开始密钥交换',algorithms_negotiated:'算法协商完成',
 host_key_received:'收到主机指纹',host_key_confirmation_required:'等待本地核对指纹',host_key_verified:'主机指纹已核验',authentication_started:'开始身份认证',
 authentication_method_started:'尝试认证方法',authentication_method_failed:'此认证方法未通过',authentication_partial:'需要继续认证',authenticated:'身份认证通过',authentication_retry:'准备重新认证',connected:'SSH 连接已建立',connection_cancelled:'连接已取消',connection_failed:'连接失败'
};
export function eventLabel(e:ConnectionEvent){return e.event==='connection_failed'?(failureLabels[String(e.data.code)]||'连接失败'):eventLabels[e.event]||e.event;}
// Deliberately allowlist display metadata: new backend fields never appear by accident.
export function eventNote(e:ConnectionEvent){return ['address','port','server_version','kex','host_key_algorithm','cipher_out','cipher_in','fingerprint','method','source','code'].filter(k=>e.data[k]!==undefined).map(k=>`${k}=${e.data[k]}`).join(' · ');}
export interface OrbitState {
 request:RequestSummary; events:ConnectionEvent[]; last:ConnectionEvent; context:ConnectionContext;
 attempt:number; stage:OrbitStage; outcome:'active'|'connected'|'reused'|'failed'|'cancelled';
 metadata:Record<string,string|number|boolean|null>; trusted:boolean; completed:Set<OrbitStage>;
 cable:number; code:string; dropped:number; waitingForTarget:boolean;
}
const completion:Record<string,OrbitStage>={dns_resolved:'dns',tcp_connected:'tcp',jump_channel_opened:'tcp',banner_received:'ssh_banner',algorithms_negotiated:'key_exchange',host_key_verified:'host_key',authenticated:'authentication',connected:'connected'};
const cableAt:Record<string,number>={connecting:.04,dns:.12,tcp:.44,proxy:.44,ssh_banner:.64,key_exchange:.77,host_key:.87,authentication:.95,connected:1};
export function deriveOrbit(request:RequestSummary,detail:RequestDetail|undefined):OrbitState|null {
 if(!detail?.connection_events?.length)return null;
 const events=[...new Map(detail.connection_events.map(e=>[e.seq,e])).values()].sort((a,b)=>a.seq-b.seq),last=events.at(-1)!;
 // Reset metadata/trust on every hop and retry, even if the previous attempt got further.
 const context=last.connection_context,attempt=last.attempt;
 const current=events.filter(e=>e.connection_context.hop_index===context.hop_index&&e.attempt===attempt);
 const metadata=Object.assign({},...current.map(e=>e.data)) as OrbitState['metadata'];
 const reused=last.event==='connection_reused',connected=last.event==='connected';
 let outcome:OrbitState['outcome']=last.event==='connection_cancelled'?'cancelled':last.event==='connection_failed'?'failed':context.role==='target'&&reused?'reused':context.role==='target'&&connected?'connected':'active';
 let code=String(metadata.code||'');
 const awaitingDetail=(request.connection_event_seq||0)>last.seq;
 if(outcome==='active'&&!awaitingDetail&&!['running','pending_approval','queued_readonly','queued_authorized'].includes(request.status)){
  outcome=['terminated','disconnected'].includes(request.status)?'cancelled':'failed';
  code=request.status==='timed_out'?'timeout':outcome==='cancelled'?'cancelled':'connection_error';
 }
 const stage=orbitStages.includes(last.stage as OrbitStage)?last.stage as OrbitStage:last.stage==='proxy'?'tcp':'dns';
 const completed=new Set(current.map(e=>completion[e.event]).filter(Boolean));
 const trusted=current.some(e=>e.event==='host_key_verified'||e.event==='connection_reused'||e.event==='connected');
 return {request,events,last,context,attempt,stage,outcome,metadata,trusted,completed,code,dropped:detail.connection_events_dropped||0,
  cable:cableAt[last.stage]??.04,waitingForTarget:context.role==='jump'&&(connected||reused)};
}
export function connectionOrbits(requests:RequestSummary[],details:Record<string,RequestDetail>){
 const result:Record<string,OrbitState>={};
 for(const r of [...requests].sort((a,b)=>Date.parse(b.created_at)-Date.parse(a.created_at))){
  if(result[r.server_id])continue;
  const state=deriveOrbit(r,details[r.request_id]);if(state)result[r.server_id]=state;
 }
 return result;
}
export function orbitTitle(o:OrbitState){
 if(o.outcome==='failed'||o.outcome==='cancelled')return failureLabels[o.code]||(o.outcome==='cancelled'?'连接已取消':'连接失败');
 if(o.outcome==='reused')return '复用已认证连接';
 if(o.outcome==='connected')return 'SSH 已连接';
 if(o.waitingForTarget)return '跳板已连接 · 等待下一跳';
 return eventLabel(o.last);
}
export function orbitElapsed(o:OrbitState,now:number,online:boolean){
 const at=Date.parse(o.last.at);
 return Math.max(0,o.last.elapsed_ms+(o.outcome==='active'&&online&&Number.isFinite(at)?Math.max(0,now-at):0));
}
