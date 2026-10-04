import {useState} from 'react';
import {eventLabel,eventNote,orbitElapsed,orbitStages,orbitTitle,stageLabels} from '../connection';
import type {OrbitState} from '../connection';
import type {Server} from '../types';
import {Fingerprint} from './Fingerprint';

export function ConnectionTelemetry({orbit}:{orbit:OrbitState}){
 return <details className="connection-telemetry" onToggle={e=>{if(e.currentTarget.open)e.currentTarget.querySelector('ol')?.scrollIntoView({block:'nearest'});}}><summary>握手记录 <span>{orbit.events.length} 条{orbit.dropped?` · 早期 ${orbit.dropped} 条已省略`:''}</span></summary>
  <ol tabIndex={0} aria-label="SSH 连接事件记录">{orbit.events.map(e=><li key={e.seq} data-event={e.event}>
   <time>+{(e.elapsed_ms/1000).toFixed(3)}s</time><div><span className="telemetry-hop">{e.connection_context.role==='jump'?'跳板':'目标'} {e.connection_context.hop_index}/{e.connection_context.hop_count} · #{e.attempt}</span><strong>{eventLabel(e)}</strong><code>{eventNote(e)}</code></div>
  </li>)}</ol>
 </details>;
}
export function OrbitPanel({orbit:o,server,now,online,onDetail}:{orbit:OrbitState;server:Server;now:number;online:boolean;onDetail:(id:string)=>void}){
 const [expanded,setExpanded]=useState(false),active=o.outcome==='active',failed=['failed','cancelled'].includes(o.outcome),open=active||failed||expanded;
 const fingerprint=String(o.metadata.fingerprint||''),m=o.metadata,context=o.context;
 const hop=`${context.role==='jump'?'跳板':'目标'} ${context.hop_index} / ${context.hop_count}`;
 const title=orbitTitle(o),elapsed=(orbitElapsed(o,now,online)/1000).toFixed(2);
 const diagnosticFailed=!active&&['failed','timed_out','disconnected'].includes(o.request.status)&&!failed;
 return <section className={'orbit-panel '+(open?'expanded':'compact')} data-state={o.outcome} data-stage={o.stage} data-seq={o.last.seq} data-attempt={o.attempt} aria-label="SSH 连接状态">
  <div className="orbit-topline"><span className="orbit-kicker">SSH <i>/</i> 连接状态</span><span className="orbit-destination">{server.label}</span><button className="text-button" onClick={()=>onDetail(o.request.request_id)}>请求详情 ↗</button></div>
  <div className="orbit-heading"><h2 aria-live="polite">{title}</h2><span className="orbit-time">{elapsed}<small>s</small></span></div>
  {(!online&&active)&&<p className="orbit-warning" role="status">本地应用暂未响应，保留最后收到的阶段。</p>}
  {diagnosticFailed&&<p className="orbit-warning">{o.request.operation==='test_connection'?'SSH 握手已成功，后续连接诊断未通过；请查看请求详情。':'SSH 握手已成功，后续任务未完成；请查看请求详情。'}</p>}
  {!active&&!server.connected&&!failed&&<p className="orbit-warning">此为上次握手记录，当前连接已断开。</p>}
  {open&&<div className="orbit-body" tabIndex={0} aria-label="连接详情"><div className="orbit-route"><span>{hop} · {context.host_alias||context.hostname}:{context.port}</span><span>尝试 {o.attempt||'—'}</span></div>
   {o.outcome==='reused'?<p className="orbit-reuse">沿用已有 SSH 会话，未重新握手。</p>:<ol className="orbit-stages" aria-label="握手阶段">{orbitStages.map((s,i)=><li key={s} data-stage={s} className={(o.completed.has(s)?'done ':'')+(s===o.stage?'current':'')} aria-current={s===o.stage?'step':undefined}><span>{o.completed.has(s)?'✓':String(i+1).padStart(2,'0')}</span>{stageLabels[s]}</li>)}</ol>}
   <div className="orbit-observation">{fingerprint&&<Fingerprint value={fingerprint} trusted={o.trusted}/>}<div className="orbit-facts">
    {m.server_version&&<p><span>版本</span><code>{String(m.server_version)}</code></p>}
    {m.kex&&<p><span>交换</span><code>{String(m.kex)}</code></p>}
    {m.cipher_out&&<p><span>加密 ↑ / ↓</span><code>{String(m.cipher_out)} / {String(m.cipher_in||'—')}</code></p>}
    {m.key_type&&<p><span>主机密钥</span><code>{String(m.key_type)} · {o.trusted?'已核验':'尚未信任'}</code></p>}
    {fingerprint&&<p><span>指纹</span><code className="orbit-fingerprint">{fingerprint}</code></p>}
    {m.expected_fingerprint&&<p><span>预期指纹</span><code>{String(m.expected_fingerprint)}</code></p>}
    {!m.server_version&&!fingerprint&&<p className="orbit-wait">{eventLabel(o.last)}<small>{context.via_host_alias?`经由 ${context.via_host_alias}`:context.hostname}</small></p>}
   </div></div><ConnectionTelemetry orbit={o}/>
  </div>}
  <div className="orbit-command"><i id="orbit-origin"/><code>$ ssh {server.ssh_target}{server.port&&server.port!==22?` -p ${server.port}`:''}</code>{!active&&!failed&&<button className="text-button" aria-expanded={expanded} onClick={()=>setExpanded(!expanded)}>{expanded?'收起':'展开详情'}</button>}</div>
  {!open&&<p className="orbit-summary">{String(m.key_type||'SSH')} · {String(m.cipher_out||'已认证')}{o.outcome==='reused'?' · 会话复用':''}</p>}
 </section>;
}
