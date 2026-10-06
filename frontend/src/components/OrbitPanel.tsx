import {useEffect,useRef,useState} from 'react';
import {copy} from '../api';
import {eventLabel,eventNote,hostKeyLabel,orbitElapsed,orbitStages,orbitTitle,softwareVersion,stageLabels} from '../connection';
import type {ConnectionEvent,OrbitState} from '../connection';
import type {Server} from '../types';
import {Fingerprint} from './Fingerprint';

// Attempt 0 is the reuse check before any network attempt; only numbered attempts are shown.
const hopText=(e:ConnectionEvent)=>`${e.connection_context.role==='jump'?'跳板':'目标'} ${e.connection_context.hop_index}/${e.connection_context.hop_count}${e.attempt?` · 第 ${e.attempt} 次`:''}`;
const recordText=(events:ConnectionEvent[])=>events.map(e=>[`+${(e.elapsed_ms/1000).toFixed(3)}s`,hopText(e),e.event,eventNote(e)].filter(Boolean).join('  ')).join('\n');
// Fades mark clipped content (orbit.css): the top once scrolled, the bottom while more remains below.
const edges=(el:HTMLElement)=>{el.toggleAttribute('data-scrolled',el.scrollTop>1);el.toggleAttribute('data-more',el.scrollHeight-el.scrollTop-el.clientHeight>1);};
// Inside the status panel, scroll only as far as the list needs; the toggle stays below the 16px top fade (orbit.css) so it can be closed again.
const reveal=(details:HTMLDetailsElement)=>{
 const list=details.querySelector('ol'),body=details.closest('.orbit-body'),summary=details.querySelector('summary');
 if(!body||!summary){list?.scrollIntoView({block:'nearest'});return;}
 const top=body.getBoundingClientRect().top-body.scrollTop,head=summary.getBoundingClientRect().top-top,end=(list||details).getBoundingClientRect().bottom-top;
 body.scrollTop=Math.min(head-16,Math.max(body.scrollTop,end-body.clientHeight));
};
// While live, the panel clock ticks with the canvas tip instead of the one-second app clock.
function OrbitClock({orbit,now,online}:{orbit:OrbitState;now:number;online:boolean}){
 const live=orbit.outcome==='active'&&online,[tick,setTick]=useState(now);
 useEffect(()=>{if(!live)return;const id=setInterval(()=>setTick(Date.now()),50);return()=>clearInterval(id);},[live]);
 return <span className="orbit-time">{(orbitElapsed(orbit,live?Math.max(now,tick):now,online)/1000).toFixed(2)}<small>s</small></span>;
}
const resolvers={jump:'跳板解析',proxy:'代理解析'};
export function ConnectionTelemetry({orbit}:{orbit:OrbitState}){
 const [copied,setCopied]=useState(''),timer=useRef<ReturnType<typeof setTimeout>|undefined>(undefined);
 useEffect(()=>()=>clearTimeout(timer.current),[]);
 const copyRecord=()=>{clearTimeout(timer.current);copy(recordText(orbit.events)).then(()=>setCopied('已复制'),()=>setCopied('复制失败')).finally(()=>{timer.current=setTimeout(()=>setCopied(''),1600);});};
 return <details className="connection-telemetry" onToggle={e=>{if(e.currentTarget.open)reveal(e.currentTarget);}}><summary>握手记录 <span>{orbit.events.length} 条{orbit.dropped?` · 早期 ${orbit.dropped} 条已省略`:''}</span></summary>
  <div className="telemetry-tools"><button type="button" className="text-button" onClick={copyRecord}>{copied||'复制记录'}</button></div>
  <ol tabIndex={0} aria-label="SSH 连接事件记录">{orbit.events.map(e=><li key={e.seq} data-event={e.event}>
   <time>+{(e.elapsed_ms/1000).toFixed(3)}s</time><div><span className="telemetry-hop">{hopText(e)}</span><strong>{eventLabel(e)}</strong><code>{eventNote(e)}</code></div>
  </li>)}</ol>
 </details>;
}
const pair=(a:unknown,b:unknown)=>!b||a===b?String(a):`${a} ↑ / ${b} ↓`;
const authStatus={trying:'进行中',failed:'未通过',partial:'需继续',ok:'通过'};
export function OrbitPanel({orbit:o,server,now,online,onDetail}:{orbit:OrbitState;server:Server;now:number;online:boolean;onDetail:(id:string)=>void}){
 const [expanded,setExpanded]=useState(false),active=o.outcome==='active',failed=['failed','cancelled'].includes(o.outcome),open=active||failed||expanded;
 const fingerprint=String(o.metadata.fingerprint||''),m=o.metadata,context=o.context;
 const hop=`${context.role==='jump'?'跳板':'目标'} ${context.hop_index} / ${context.hop_count}`;
 const title=orbitTitle(o),elapsed=(orbitElapsed(o,now,online)/1000).toFixed(2);
 // The heading already names the latest event; the wait line adds where it is happening.
 const waiting=eventLabel(o.last),where=m.address?`${m.address}:${m.port??context.port}`:context.via_host_alias?`经由 ${context.via_host_alias}`:context.hostname;
 const diagnosticFailed=!active&&['failed','timed_out','disconnected'].includes(o.request.status)&&!failed;
 // AEAD ciphers authenticate inside the cipher; Paramiko still reports an unused HMAC name for them.
 const aead=/gcm|poly1305/.test(String(m.cipher_out||'')),compressed=[m.compression_out,m.compression_in].some(v=>v&&v!=='none');
 const summary=[o.outcome==='reused'?'会话复用':elapsed+'s',m.key_type,m.cipher_out,o.outcome==='reused'?'':m.auth_method].filter(Boolean).join(' · ');
 // Until the key is trusted, its state stays above the scrolling body so an open log cannot push it away.
 const pinTrust=!!m.key_type&&['pending','mismatch','rejected'].includes(o.hostKey);
 const keyRow=(className?:string)=><p className={className} data-host-key={o.hostKey}><span>主机密钥</span><code>{String(m.key_type)}{m.host_key_algorithm&&m.host_key_algorithm!==m.key_type?` (${m.host_key_algorithm})`:''} · {hostKeyLabel(o)}</code></p>;
 const body=useRef<HTMLDivElement>(null);
 useEffect(()=>{const el=body.current;if(!el)return;edges(el);const watch=new ResizeObserver(()=>edges(el));watch.observe(el);for(const child of el.children)watch.observe(child);return()=>watch.disconnect();},[open,o.last.seq,o.outcome]);
 return <section className={'orbit-panel '+(open?'expanded':'compact')} data-state={o.outcome} data-stage={o.stage} data-seq={o.last.seq} data-attempt={o.attempt} data-encrypted={o.encrypted} aria-label="SSH 连接状态">
  <div className="orbit-topline"><span className="orbit-kicker">SSH <i>/</i> 连接状态</span><span className="orbit-destination">{server.label}</span><button className="text-button" onClick={()=>onDetail(o.request.request_id)}>请求详情 ↗</button></div>
  <div className="orbit-heading"><h2 aria-live="polite">{title}</h2><OrbitClock orbit={o} now={now} online={online}/></div>
  {(!online&&active)&&<p className="orbit-warning" role="status">本地应用暂未响应，保留最后收到的阶段。</p>}
  {diagnosticFailed&&<p className="orbit-warning">{o.request.operation==='test_connection'?'SSH 握手已成功，后续连接诊断未通过；请查看请求详情。':'SSH 握手已成功，后续任务未完成；请查看请求详情。'}</p>}
  {o.hostKey==='mismatch'&&<p className="orbit-warning danger">服务器公钥与 known_hosts 中已保存的记录不一致。可能是服务器重装或更换了密钥，也可能存在中间人；请通过可信渠道核实后再手动更新 known_hosts。</p>}
  {!active&&!server.connected&&!failed&&<p className="orbit-warning">此为上次握手记录，当前连接已断开。</p>}
  {open&&pinTrust&&keyRow('orbit-trust')}
  {open&&<div className="orbit-body" ref={body} tabIndex={0} aria-label="连接详情" onScroll={e=>edges(e.currentTarget)}><div className="orbit-route"><span>{hop} · {context.via_host_alias?`经由 ${context.via_host_alias} → `:''}{context.host_alias||context.hostname}:{context.port}</span><span>{o.attempt?`第 ${o.attempt} 次尝试`:'复用检查'}</span></div>
   {o.outcome==='reused'?<p className="orbit-reuse">沿用已有 SSH 会话，未重新握手。</p>:<ol className="orbit-stages" aria-label="握手阶段">{orbitStages.map((s,i)=>{
    const done=o.completed.has(s),delegated=s==='dns'&&!done&&o.resolver!=='local'?resolvers[o.resolver]:'';
    return <li key={s} data-stage={s} className={(done?'done ':delegated?'delegated ':'')+(s===o.stage?'current':'')} aria-current={s===o.stage?'step':undefined}><span>{done?'✓':delegated?'—':String(i+1).padStart(2,'0')}</span>{delegated||stageLabels[s]}</li>;
   })}</ol>}
   <div className="orbit-observation">{fingerprint&&<Fingerprint value={fingerprint} state={o.hostKey} expected={String(m.expected_fingerprint||'')}/>}<div className="orbit-facts">
    {m.server_version&&<p><span>服务端</span><code>{softwareVersion(m.server_version)}</code></p>}
    {m.kex&&<p><span>密钥交换</span><code>{String(m.kex)}</code></p>}
    {m.key_type&&!pinTrust&&keyRow()}
    {m.cipher_out&&<p><span>加密</span><code>{pair(m.cipher_out,m.cipher_in)}</code></p>}
    {m.cipher_out&&(aead||m.mac_out)&&<p><span>完整性</span><code>{aead?'由加密算法内含 (AEAD)':pair(m.mac_out,m.mac_in)}</code></p>}
    {compressed&&<p><span>压缩</span><code>{pair(m.compression_out,m.compression_in)}</code></p>}
    {o.auth.length>0&&<p><span>认证</span><code>{o.auth.map(a=>`${a.method}${a.count>1?` ×${a.count}`:''} ${authStatus[a.status]}`).join(' · ')}</code></p>}
    {fingerprint&&<p><span>指纹</span><code className="orbit-fingerprint">{fingerprint}</code></p>}
    {m.expected_fingerprint&&<p><span>已保存指纹</span><code>{String(m.expected_fingerprint)}</code></p>}
    {!m.server_version&&!fingerprint&&<p className={'orbit-wait'+(waiting===title?' bare':'')}>{waiting!==title&&waiting}<small>{where}</small></p>}
   </div></div><ConnectionTelemetry orbit={o}/>
  </div>}
  <div className="orbit-command"><i id="orbit-origin"/><code>$ ssh {server.ssh_target}{server.port&&server.port!==22?` -p ${server.port}`:''}</code>{!active&&!failed&&<button className="text-button" aria-expanded={expanded} onClick={()=>setExpanded(!expanded)}>{expanded?'收起':'展开详情'}</button>}</div>
  {!open&&<p className="orbit-summary">{summary}</p>}
 </section>;
}
