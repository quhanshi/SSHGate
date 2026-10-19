import {useCallback,useEffect,useRef,useState} from 'react';
import {api} from './api';
import {active,clean,statusLabels} from './utils';
import {connectedRecord} from './connection';
import type {Line,RequestDetail,RequestSummary,Snapshot} from './types';
interface Cursor {out:number;err:number;signature:string;started:boolean;finished:boolean;progress:number;events:number;partial:Record<string,number|null>;key:Record<string,boolean>}
export function useDesktop(){
 const [data,setData]=useState<Snapshot|null>(null),[online,setOnline]=useState(false),[error,setError]=useState('');
 const [lines,setLines]=useState<Line[]>([]),[details,setDetails]=useState<Record<string,RequestDetail>>({});
 const dataRef=useRef(data),running=useRef(false),mounted=useRef(true),seq=useRef(0),cursor=useRef(new Map<string,Cursor>()),detailRef=useRef<Record<string,RequestDetail>>({});
 const rowRef=useRef<Line[]>([]),rowById=useRef(new Map<number,Line>()),rowVersion=useRef(0),committedVersion=useRef(-1),terrain=useRef<string[]>([]),retry=useRef(new Map<string,number>()),tick=useRef(0);
 const commit=useCallback(()=>{
  if(committedVersion.current===rowVersion.current)return;
  committedVersion.current=rowVersion.current;
  terrain.current=terrain.current.slice(-80);
  setLines(previous=>{const saved=new Map(previous.map(l=>[l.id,l]));return rowRef.current.map(l=>{
   const p=saved.get(l.id);return p&&p.raw===l.raw&&p.count===l.count&&p.privateKey===l.privateKey?p:{...l};
  });});
 },[]);
 const push=useCallback((r:RequestSummary,kind:Line['kind'],raw:string,animate=true)=>{
  const rows=rowRef.current,last=rows.at(-1);
  // Output pages may end inside a line. Collapse only after its newline arrives.
  if(last&&last.request===r.request_id&&last.kind===kind&&last.raw===raw&&!['cmd','out','err'].includes(kind)){last.count++;rowVersion.current++;return last.id;}
  const row={id:++seq.current,server:r.server_id,request:r.request_id,kind,raw,count:1,at:Date.now(),animate};
  rows.push(row);rowById.current.set(row.id,row);rowVersion.current++;
  // Keep the stream bounded even before the current page finishes parsing.
  if(rows.length>500){const retired=rows.shift()!;rowById.current.delete(retired.id);
   terrain.current.push(retired.privateKey?'••••':retired.raw);
   if(terrain.current.length>160)terrain.current=terrain.current.slice(-80);
  }
  return row.id;
 },[]);
 const chunk=useCallback((r:RequestSummary,c:Cursor,stream:'out'|'err',text:string,bulk:boolean)=>{
  const pieces=clean(text).replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n');
  for(let i=0;i<pieces.length;i++){
   if(pieces[i]){
    const id=c.partial[stream],existing=id?rowById.current.get(id):null;
    if(existing){existing.raw+=pieces[i];rowVersion.current++;}else c.partial[stream]=push(r,stream,pieces[i],!bulk);
   }
   const current=rowById.current.get(c.partial[stream]??-1);
   if(current&&(c.key[stream]||/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(current.raw))){if(!current.privateKey)rowVersion.current++;current.privateKey=true;c.key[stream]=true;}
   if(i<pieces.length-1){
    if(!pieces[i]&&c.partial[stream]===null)c.partial[stream]=push(r,stream,'',!bulk);
    const id=c.partial[stream],row=rowById.current.get(id??-1),index=row?rowRef.current.indexOf(row):-1,prev=index>0?rowRef.current[index-1]:undefined;
    if(row){terrain.current.push(row.privateKey?'••••':row.raw);terrain.current=terrain.current.slice(-80);}
    if(row&&prev&&prev.request===row.request&&prev.kind===row.kind&&prev.raw===row.raw){prev.count++;rowVersion.current++;rowRef.current.splice(index,1);rowById.current.delete(row.id);}
    if(current&&/-----END [A-Z ]*PRIVATE KEY-----/.test(current.raw))c.key[stream]=false;
    c.partial[stream]=null;
   }
  }
 },[push]);
 const refresh=useCallback(async()=>{
  if(running.current||!window.pywebview?.api||!mounted.current)return;running.current=true;
  try{
   const snapshot=await api('snapshot');if(!mounted.current)return;dataRef.current=snapshot;setData(snapshot);setOnline(true);setError('');tick.current++;
   let detailsChanged=false;const known=new Set(snapshot.requests.map(r=>r.request_id));for(const id of cursor.current.keys())if(!known.has(id)){cursor.current.delete(id);if(id in detailRef.current){delete detailRef.current[id];detailsChanged=true;}}
   // Rotate recent completed requests so a long output never blocks active approvals.
   const recent=snapshot.requests.slice(0,24).filter(r=>!active(r));
   const activeRequests=snapshot.requests.filter(active);
   // Prioritize approvals over historical output so slow transcripts never hide a new review.
   const candidates=[...activeRequests.filter(r=>r.status==='pending_approval').reverse(),
    ...activeRequests.filter(r=>r.status==='running').reverse(),
    ...activeRequests.filter(r=>r.status!=='pending_approval'&&r.status!=='running').reverse(),
    ...recent.slice(tick.current%6),...recent.slice(0,tick.current%6)];
   let budget=12;
   for(const r of candidates){
    let c=cursor.current.get(r.request_id);
    if(!c){c={out:0,err:0,signature:'',started:false,finished:false,progress:-1,events:0,partial:{out:null,err:null},key:{out:false,err:false}};cursor.current.set(r.request_id,c);}
    const signature=[r.status,r.output_bytes,r.phase,r.progress_bytes,r.connection_event_seq].join('|');
    const cached=detailRef.current[r.request_id];const unread=cached&&(c.out<cached.stdout_length||c.err<cached.stderr_length);
    if(c.signature===signature&&!unread)continue;
    if(budget<=0)break;if((retry.current.get(r.request_id)||0)>Date.now())continue;budget--;
    try{
     const offset=c.out===c.err?c.out:Math.max(c.out,c.err);
     const d=await api('request_detail',r.request_id,offset);if(!mounted.current)return;
     detailRef.current[r.request_id]=d;detailsChanged=true;c.signature=signature;
     if(!c.started){push(r,'cmd',d.command);terrain.current.push(d.command);c.started=true;}
     const bulk=d.stdout_length+d.stderr_length>4000||d.stdout.split('\n').length+d.stderr.split('\n').length>40;
     // A new SSH connection folds into one log line before its output; reuse adds nothing.
     for(const e of d.connection_events||[]){if(e.seq<=c.events)continue;c.events=e.seq;if(e.event==='connected'&&e.connection_context.role==='target')push(r,'ok',connectedRecord(e),!bulk);}
     for(const stream of ['out','err'] as const){
      const field=stream==='out'?'stdout':'stderr',length=d[field+'_length' as 'stdout_length'|'stderr_length'];
      if(c[stream]>=length)continue;
      let part=d;
      if(offset!==c[stream]){if(budget<=0)continue;budget--;part=await api('request_detail',r.request_id,c[stream]);}
      const text=part[field];chunk(r,c,stream,text,bulk);c[stream]+=text.length;
     }
     if(r.progress_bytes&&r.progress_bytes!==c.progress){push(r,'meta',`传输 ${r.progress_bytes} / ${d.total_bytes??'?'} bytes`,false);c.progress=r.progress_bytes;}
     if(!active(r)&&!c.finished&&c.out>=d.stdout_length&&c.err>=d.stderr_length){push(r,r.status==='succeeded'?'ok':['denied','expired'].includes(r.status)?'warn':'err',`${statusLabels[r.status]} · 退出码 ${r.exit_code??'—'}${r.error?' · '+r.error:''}`);c.finished=true;}
    }catch(e){retry.current.set(r.request_id,Date.now()+2500);}
   }
   commit();if(detailsChanged)setDetails({...detailRef.current});
  }catch(e){if(mounted.current){setOnline(false);setError(e instanceof Error?e.message:String(e));}}
  finally{running.current=false;}
 },[push,chunk,commit]);
 useEffect(()=>{
  mounted.current=true;let timer:ReturnType<typeof setTimeout>|undefined,stopped=false;
  const loop=async()=>{await refresh();if(!stopped)timer=setTimeout(loop,document.hidden?1800:650);};
  const ready=()=>{void refresh();};window.addEventListener('pywebviewready',ready);void loop();
  return()=>{stopped=true;mounted.current=false;clearTimeout(timer);window.removeEventListener('pywebviewready',ready);};
 },[refresh]);
 return {data,online,error,lines,details,refresh,terrain};
}
