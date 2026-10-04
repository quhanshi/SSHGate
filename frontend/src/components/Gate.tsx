import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {api} from '../api';
import {risk} from '../utils';
import {DisplayText} from './Text';
import type {RequestDetail,RequestSummary} from '../types';
export function useHoldApproval(onDone:(id:string)=>Promise<void>,onError:(e:unknown)=>void){
 const [holding,setHolding]=useState<{id:string;progress:number}|null>(null),[busy,setBusy]=useState<string|null>(null);
 const generation=useRef(0),frame=useRef<number|null>(null),live=useRef<{id:string;gen:number}|null>(null),busyRef=useRef(false);
 const stop=useCallback(()=>{generation.current++;live.current=null;if(frame.current!==null)cancelAnimationFrame(frame.current);frame.current=null;setHolding(null);},[]);
 const begin=useCallback(async(id:string)=>{
  if(live.current||busyRef.current)return;const gen=++generation.current;live.current={id,gen};setHolding({id,progress:0});
  try{
   const review=await api('begin_review',id);
   if(live.current?.gen!==gen)return;
   const duration=500,start=performance.now(),remaining=review.request.approval_remaining_ms??review.request.approval_expires_in_seconds*1000;
   const advance=(now:number)=>{
    if(now-start>=remaining){stop();return;}
    if(live.current?.gen!==gen)return;const progress=Math.min(1,(now-start)/duration);setHolding({id,progress});
    if(progress<1){frame.current=requestAnimationFrame(advance);return;}
    live.current=null;frame.current=null;setHolding(null);busyRef.current=true;setBusy(id);
    void api('approve',id,review.ticket,true).then(()=>onDone(id)).catch(onError).finally(()=>{busyRef.current=false;setBusy(null);});
   };frame.current=requestAnimationFrame(advance);
  }catch(e){if(live.current?.gen===gen){stop();onError(e);}}
 },[onDone,onError,stop]);
 useEffect(()=>{const cancel=()=>stop();const hide=()=>{if(document.hidden)stop();};window.addEventListener('blur',cancel);window.addEventListener('pointerup',cancel);window.addEventListener('pointercancel',cancel);window.addEventListener('keyup',cancel);document.addEventListener('visibilitychange',hide);return()=>{stop();window.removeEventListener('blur',cancel);window.removeEventListener('pointerup',cancel);window.removeEventListener('pointercancel',cancel);window.removeEventListener('keyup',cancel);document.removeEventListener('visibilitychange',hide);};},[stop]);
 return {holding,busy,begin,stop};
}
export type Hold=ReturnType<typeof useHoldApproval>;
export function Gate({requests,details,selected,onSelect,open,onToggle,onReject,onDetail,hold,leaving}:{requests:RequestSummary[];details:Record<string,RequestDetail>;selected:string|null;onSelect:(id:string)=>void;open:boolean;onToggle:(open:boolean)=>void;onReject:(id:string)=>void;onDetail:(id:string)=>void;hold:Hold;leaving:Record<string,string>}){
 const [expanded,setExpanded]=useState(new Set<string>()),listRef=useRef<HTMLDivElement>(null);
 const [now,setNow]=useState(performance.now());
 const sample=useMemo(()=>({at:performance.now(),requests}),[requests]);
 useEffect(()=>{const timer=setInterval(()=>setNow(performance.now()),100);return()=>clearInterval(timer);},[]);
 const pending=requests.filter(r=>r.status==='pending_approval'||leaving[r.request_id]);
 const anyRunning=requests.some(r=>r.status==='running');
 useEffect(()=>{if(selected)listRef.current?.querySelector(`[data-request-id="${CSS.escape(selected)}"]`)?.scrollIntoView({block:'nearest'});},[selected]);
 return <aside className={'gate '+(open?'open':'')} id="gate" aria-label="请求审批">
  <button className="gate-rail" id="gate-rail" onClick={()=>onToggle(true)} aria-label="展开请求审批"><span>审批</span><b id="gate-rail-count">{pending.length}</b></button>
  <div className="gate-head"><div><h2>请求审批</h2><span id="gate-count">{pending.length?`${pending.length} 条请求等待审批`:'没有待审请求'}</span></div><button className="icon-button gate-collapse" id="gate-collapse" onClick={()=>onToggle(false)} aria-label="收起请求审批">×</button></div>
  <div className="gate-list" id="gate-list" ref={listRef}>{pending.length?pending.map(r=>{
   const d=details[r.request_id],kind=risk(d||r),progress=hold.holding?.id===r.request_id?hold.holding.progress:0,loading=!d;
   const remaining=Math.max(0,(r.approval_remaining_ms??r.approval_expires_in_seconds*1000)-Math.max(0,now-sample.at)),countdown=Math.min(1,remaining/((r.approval_timeout_seconds??60)*1000)),blocked=anyRunning&&r.operation!=='request_auto_approval';
   return <article key={r.request_id} data-request-id={r.request_id} tabIndex={0} onFocus={()=>onSelect(r.request_id)} onClick={()=>onSelect(r.request_id)} className={`gate-item ${kind} ${selected===r.request_id?'active':''} ${expanded.has(r.request_id)?'expanded':''} ${leaving[r.request_id]||''}`}>
    <div className="gi-top"><span>{r.server_label}</span><span className="risk">{r.operation==='request_auto_approval'?'临时授权':kind==='destructive'?'破坏性':kind==='readonly'?'只读':'写入 / 人工'}</span></div>
    <pre className="gi-cmd"><DisplayText text={d?.command||r.command_preview} danger/></pre>
    <div className="gi-why"><b>{d?.readonly_explanation||'正在读取完整请求…'}</b><br/>{r.reason}</div>
    <div className="gi-meta">{d?`${d.cwd} · ${d.timeout_seconds}s`:'正在核对参数'}</div>
    <div className="gi-detail">{d&&<><span>{d.ssh_settings.username}@{d.ssh_settings.hostname}:{d.ssh_settings.port}</span><br/><DisplayText text={d.executed_command}/><br/><span>SHA256 {d.digest}</span></>}</div>
    <div className="gi-actions"><button className={'hold '+(hold.busy===r.request_id?'done':'')} style={{'--p':progress,'--remaining':countdown} as React.CSSProperties} disabled={loading||blocked||remaining<=0||!!hold.busy||!!leaving[r.request_id]} onPointerDown={event=>{if(event.button!==0)return;event.preventDefault();event.currentTarget.focus();onSelect(r.request_id);void hold.begin(r.request_id);}} onPointerLeave={hold.stop} onKeyDown={e=>{if([' ','Enter'].includes(e.key)){e.preventDefault();if(!e.repeat)void hold.begin(r.request_id);}}} onKeyUp={hold.stop} aria-label={`按住批准 ${r.server_label}`}><i className="countdown" aria-hidden="true"/><i className="fill" aria-hidden="true"/><span>{hold.busy===r.request_id?'正在批准':blocked?'等待当前执行结束':remaining<=0?'审批已过期':'按住 0.5 秒批准'}</span>{!hold.busy&&<span className="countdown-number" aria-label="待审批剩余时间">{Math.ceil(remaining/1000)}s</span>}</button><button className="gi-reject" disabled={!!hold.busy||!!leaving[r.request_id]} onClick={e=>{e.stopPropagation();hold.stop();onReject(r.request_id);}}>拒绝</button></div>
    <div className="gi-links"><button className="gi-more" onClick={()=>setExpanded(prev=>{const next=new Set(prev);next.has(r.request_id)?next.delete(r.request_id):next.add(r.request_id);return next;})}>{expanded.has(r.request_id)?'收起命令':'展开命令'}</button><button className="gi-more" onClick={()=>onDetail(r.request_id)}>完整请求 ↗</button></div>
   </article>;
  }):<div className="gate-empty"><span className="gate-mark">✓</span><br/>没有请求等待审批<br/><span>只读请求按本地策略自动放行。</span></div>}</div>
  <div className="gate-keys"><kbd>J</kbd><kbd>K</kbd> 切换 · 按住 <kbd>A</kbd> 批准<br/><kbd>R</kbd> 拒绝 · <kbd>Enter</kbd> 详情</div>
 </aside>;
}
