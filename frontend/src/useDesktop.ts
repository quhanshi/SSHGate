import {useCallback,useEffect,useRef,useState} from 'react';
import {api} from './api';
import {active,clean,statusLabels} from './utils';
import type {Line,RequestDetail,RequestSummary,Snapshot} from './types';
interface Cursor {out:number;err:number;signature:string;started:boolean;finished:boolean;progress:number;partial:Record<string,number|null>;key:Record<string,boolean>}
export function useDesktop(){
 const [data,setData]=useState<Snapshot|null>(null),[online,setOnline]=useState(false),[error,setError]=useState('');
 const [lines,setLines]=useState<Line[]>([]),[details,setDetails]=useState<Record<string,RequestDetail>>({});
 const dataRef=useRef(data),running=useRef(false),mounted=useRef(true),seq=useRef(0),cursor=useRef(new Map<string,Cursor>()),detailRef=useRef<Record<string,RequestDetail>>({});
 const rowRef=useRef<Line[]>([]),terrain=useRef<string[]>([]),retry=useRef(new Map<string,number>()),tick=useRef(0);
 const commit=useCallback(()=>{const old=rowRef.current.splice(0,Math.max(0,rowRef.current.length-500));if(old.length)terrain.current.push(...old.map(l=>l.privateKey?'••••':l.raw));terrain.current=terrain.current.slice(-80);setLines(previous=>{const saved=new Map(previous.map(l=>[l.id,l]));return rowRef.current.map(l=>{const p=saved.get(l.id);return p&&p.raw===l.raw&&p.count===l.count&&p.privateKey===l.privateKey?p:{...l};});});},[]);
 const push=useCallback((r:RequestSummary,kind:Line['kind'],raw:string,animate=true)=>{
  const rows=rowRef.current,last=rows.at(-1);
  // Output pages may end inside a line. Collapse only after its newline arrives.
  if(last&&last.request===r.request_id&&last.kind===kind&&last.raw===raw&&!['cmd','out','err'].includes(kind)){last.count++;return last.id;}
  const row={id:++seq.current,server:r.server_id,request:r.request_id,kind,raw,count:1,at:Date.now(),animate};rows.push(row);return row.id;
 },[]);
 const chunk=useCallback((r:RequestSummary,c:Cursor,stream:'out'|'err',text:string,bulk:boolean)=>{
  const pieces=clean(text).replace(/\r\n/g,'\n').replace(/\r/g,'\n').split('\n');
  for(let i=0;i<pieces.length;i++){
   if(pieces[i]){
    const id=c.partial[stream],existing=id?rowRef.current.find(x=>x.id===id):null;
    if(existing)existing.raw+=pieces[i];else c.partial[stream]=push(r,stream,pieces[i],!bulk);
   }
   const current=rowRef.current.find(x=>x.id===c.partial[stream]);
   if(current&&(c.key[stream]||/-----BEGIN [A-Z ]*PRIVATE KEY-----/.test(current.raw))){current.privateKey=true;c.key[stream]=true;}
   if(i<pieces.length-1){
    if(!pieces[i]&&c.partial[stream]===null)c.partial[stream]=push(r,stream,'',!bulk);
    const id=c.partial[stream],index=rowRef.current.findIndex(x=>x.id===id),row=rowRef.current[index],prev=rowRef.current[index-1];
    if(row){terrain.current.push(row.privateKey?'••••':row.raw);terrain.current=terrain.current.slice(-80);}
    if(row&&prev&&prev.request===row.request&&prev.kind===row.kind&&prev.raw===row.raw){prev.count++;rowRef.current.splice(index,1);}
    if(current&&/-----END [A-Z ]*PRIVATE KEY-----/.test(current.raw))c.key[stream]=false;
    c.partial[stream]=null;
   }
  }
 },[push]);
 const refresh=useCallback(async()=>{
  if(running.current||!window.pywebview?.api||!mounted.current)return;running.current=true;
  try{
   const snapshot=await api('snapshot');if(!mounted.current)return;dataRef.current=snapshot;setData(snapshot);setOnline(true);setError('');tick.current++;
   const known=new Set(snapshot.requests.map(r=>r.request_id));for(const id of cursor.current.keys())if(!known.has(id)){cursor.current.delete(id);delete detailRef.current[id];}
   // Rotate recent completed requests so a long output never blocks active approvals.
   const recent=snapshot.requests.slice(0,24).filter(r=>!active(r));const candidates=[...snapshot.requests.filter(active),...recent.slice(tick.current%6),...recent.slice(0,tick.current%6)].sort((a,b)=>Date.parse(a.created_at)-Date.parse(b.created_at));
   let budget=12;
   for(const r of candidates){
    let c=cursor.current.get(r.request_id);
    if(!c){c={out:0,err:0,signature:'',started:false,finished:false,progress:-1,partial:{out:null,err:null},key:{out:false,err:false}};cursor.current.set(r.request_id,c);}
    const signature=[r.status,r.output_bytes,r.phase,r.progress_bytes].join('|');
    const cached=detailRef.current[r.request_id];const unread=cached&&(c.out<cached.stdout_length||c.err<cached.stderr_length);
    if(c.signature===signature&&!unread)continue;
    if(budget<=0)break;if((retry.current.get(r.request_id)||0)>Date.now())continue;budget--;
    try{
     const offset=c.out===c.err?c.out:Math.max(c.out,c.err);
     const d=await api('request_detail',r.request_id,offset);if(!mounted.current)return;
     detailRef.current[r.request_id]=d;c.signature=signature;
     if(!c.started){push(r,'cmd',d.command);terrain.current.push(d.command);c.started=true;}
     const bulk=d.stdout_length+d.stderr_length>4000||d.stdout.split('\n').length+d.stderr.split('\n').length>40;
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
   terrain.current=terrain.current.slice(-80);commit();setDetails({...detailRef.current});
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
