import {useEffect,useRef,useState} from 'react';
import type {Drawer,Snapshot} from '../types';
type Seg='tunnel'|'mcp'|'ssh';type Hop='chatgpt'|'tunnel'|'mcp'|'ssh';
interface Pulse {id:number;seg:Seg;back:boolean;delay:number}
interface Hit {id:number;back:boolean;delay:number}
interface Seen {received:number;answered:number;requests:Map<string,{ran:boolean;bytes:number}>}
// Seconds for one light to cross a segment; the node it reaches pings on arrival.
const HOP=.42;
const ARRIVE:Record<Seg,[Hop,Hop]>={tunnel:['tunnel','chatgpt'],mcp:['mcp','tunnel'],ssh:['ssh','mcp']};
// Animates real traffic only: MCP POST counters from the local host, plus request start and new output from snapshots.
export function LinkBar({data,animate,onOpen}:{data:Snapshot|null;animate:boolean;onOpen:(page:Drawer)=>void}){
 const [pulses,setPulses]=useState<Pulse[]>([]),[hits,setHits]=useState<Partial<Record<Hop,Hit>>>({});
 const seen=useRef<Seen|null>(null),seq=useRef(0),timers=useRef(new Set<ReturnType<typeof setTimeout>>());
 useEffect(()=>()=>timers.current.forEach(clearTimeout),[]);
 useEffect(()=>{
  if(!data)return;
  const received=data.mcp.calls_received??0,answered=data.mcp.calls_answered??0,before=seen.current;
  seen.current={received,answered,requests:new Map(data.requests.map(r=>[r.request_id,{ran:!!r.approved_at,bytes:r.output_bytes}]))};
  if(!before||!animate)return;
  const added:Pulse[]=[],hit:Partial<Record<Hop,Hit>>={},via=data.tunnel.ready;
  const send=(segs:Seg[],back:boolean,start:number)=>segs.forEach((seg,i)=>{const delay=start+i*HOP;added.push({id:++seq.current,seg,back,delay});hit[ARRIVE[seg][back?1:0]]={id:seq.current,back,delay:delay+HOP};});
  // Several calls between two polls show as up to three staggered lights.
  const inbound=Math.min(3,Math.max(0,received-before.received)),outbound=Math.min(3,Math.max(0,answered-before.answered));
  for(let k=0;k<inbound;k++){if(via)send(['tunnel','mcp'],false,k*.16);else hit.mcp={id:++seq.current,back:false,delay:k*.16};}
  for(let k=0;k<outbound;k++)if(via)send(['mcp','tunnel'],true,(inbound?2*HOP:0)+k*.16);
  let started=false,output=false;
  for(const r of data.requests){const prev=before.requests.get(r.request_id);if(r.approved_at&&!prev?.ran)started=true;if(prev&&r.output_bytes>prev.bytes)output=true;}
  const ssh=inbound&&via?2*HOP:0;
  if(started)send(['ssh'],false,ssh);
  if(output)send(['ssh'],true,ssh+(started?HOP:0));
  if(!added.length&&!hit.mcp)return;
  setPulses(p=>[...p,...added].slice(-24));setHits(h=>({...h,...hit}));
  const ids=new Set(added.map(p=>p.id)),end=Math.max(0,...added.map(p=>p.delay))+HOP+.1;
  const timer=setTimeout(()=>{timers.current.delete(timer);setPulses(p=>p.filter(x=>!ids.has(x.id)));},end*1000);timers.current.add(timer);
 },[data,animate]);
 useEffect(()=>{if(!animate){setPulses([]);setHits({});}},[animate]);
 const segment=(seg:Seg,state:string,flow=false)=><span className={`chain-seg ${state} ${flow&&animate?'flow':''}`} id={'seg-'+seg}>{pulses.filter(p=>p.seg===seg).map(p=><i key={p.id} className={'pulse '+(p.back?'back':'')} style={{animationDelay:p.delay+'s'}}/>)}</span>;
 const lamp=(hop:Hop)=>{const h=animate&&hits[hop];return <i className="lamp">{h&&<b key={h.id} className={'ping '+(h.back?'back':'')} style={{animationDelay:h.delay+'s'}}/>}</i>;};
 const connected=data?.servers.filter(s=>s.connected).length||0,running=!!data?.requests.some(r=>r.status==='running'),waiting=(data?.mcp.calls_received??0)>(data?.mcp.calls_answered??0);
 return <nav className="chain" aria-label="接入链路">
  <button className={'chain-node '+(data?.tunnel.ready?'ok':'')} id="chain-chatgpt" onClick={()=>onOpen('tunnel')} title="隧道就绪表示通路可用，无法确认 ChatGPT 会话状态">{lamp('chatgpt')}ChatGPT</button>
  {segment('tunnel',data?.tunnel.ready?'ok':'')}
  <button className={'chain-node '+(data?.tunnel.ready?'ok':data?.tunnel.running?'warn':'bad')} id="chain-tunnel" onClick={()=>onOpen('tunnel')}>{lamp('tunnel')}Tunnel<small>{data?.tunnel.ready?'READY':data?.tunnel.running?'连接中':'未启动'}</small></button>
  {segment('mcp',data?.mcp.running?'ok':'bad')}
  <button className={'chain-node '+(data?.mcp.running?'ok':'bad')+(waiting&&animate?' busy':'')} id="chain-mcp" onClick={()=>onOpen('settings')} title={waiting?'有 MCP 调用正在等待返回':undefined}>{lamp('mcp')}MCP<small>:{data?.mcp.port||'—'}</small></button>
  {segment('ssh',connected?'ok':'',running)}
  <button className={'chain-node '+(connected?'ok':'')} id="chain-ssh" onClick={()=>onOpen('connections')}>{lamp('ssh')}SSH<small>{connected} / {data?.servers.length||0}</small></button>
 </nav>;
}
