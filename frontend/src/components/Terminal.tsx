import {memo,useEffect,useLayoutEffect,useRef,useState} from 'react';
import {DisplayText} from './Text';
import {redactWithMap} from '../utils';
import type {Line,RequestSummary} from '../types';
const TerminalRow=memo(function TerminalRow({line,effects}:{line:Line;effects:boolean}){
 const [length,setLength]=useState(line.raw.length);
 const first=useRef(true);
 useEffect(()=>{
  if(!first.current||!effects||!line.animate||line.raw.length>700){setLength(line.raw.length);first.current=false;return;}
  first.current=false;setLength(0);const start=performance.now(),duration=Math.min(700,line.raw.length*3);let frame:number;
  const animate=(now:number)=>{const n=Math.min(line.raw.length,Math.ceil((now-start)/duration*line.raw.length));setLength(n);if(n<line.raw.length)frame=requestAnimationFrame(animate);};frame=requestAnimationFrame(animate);return()=>cancelAnimationFrame(frame);
 },[line.raw,effects,line.animate]);
 // Redact the complete source before slicing, so typing never reveals a partial secret.
 const display=line.privateKey?'••••':redactWithMap(line.raw).text;
 const shown=length>=line.raw.length?display:display.slice(0,Math.round(length/Math.max(1,line.raw.length)*display.length));
 return <div className={`tl ${line.kind} ${line.animate?'in':''}`} data-line={line.id}><span className="line-text">{line.kind==='cmd'&&<span className="ps">$ </span>}<DisplayText text={shown}/></span>{line.count>1&&<span className="rep"> ×{line.count}</span>}</div>;
});
export function Terminal({lines,focus,effects,requests,onRequest,onClear,onTerrain}:{lines:Line[];focus:string|null;effects:boolean;requests:RequestSummary[];onRequest:(id:string)=>void;onClear:()=>void;onTerrain:(rows:string[])=>void}){
 const ref=useRef<HTMLDivElement>(null),hover=useRef(false),pinned=useRef(true),[paused,setPaused]=useState(false);
 const visible=focus?lines.filter(l=>l.server===focus):lines;
 const retired=useRef(new Set<number>()),lastScroll=useRef(0);
 const scroll=()=>{
  const el=ref.current!;pinned.current=el.scrollHeight-el.scrollTop-el.clientHeight<36;if(!hover.current)setPaused(!pinned.current);
  if(performance.now()-lastScroll.current<160||el.scrollTop<20)return;lastScroll.current=performance.now();
  const top=el.getBoundingClientRect().top,rows:string[]=[];
  for(const node of el.querySelectorAll<HTMLElement>('[data-line]')){
   if(node.getBoundingClientRect().bottom>=top)break;const id=Number(node.dataset.line);if(retired.current.has(id))continue;
   const row=visible.find(l=>l.id===id);if(row){retired.current.add(id);rows.push(row.privateKey?'••••':row.raw);}
  }
  if(rows.length)onTerrain(rows.slice(-16));if(retired.current.size>600)retired.current=new Set(visible.filter(l=>retired.current.has(l.id)).map(l=>l.id));
 };
 useLayoutEffect(()=>{const el=ref.current;if(el&&pinned.current&&!hover.current&&!window.getSelection()?.toString())el.scrollTop=el.scrollHeight;},[visible.length,visible.at(-1)?.raw,visible.at(-1)?.count]);
 const copySelection=(event:React.ClipboardEvent)=>{
  const selection=window.getSelection();if(!selection?.rangeCount||selection.isCollapsed)return;
  const range=selection.getRangeAt(0),container=ref.current;if(!container?.contains(range.commonAncestorContainer))return;
  const parts:string[]=[];
  for(const row of container.querySelectorAll<HTMLElement>('[data-line]')){
   if(!range.intersectsNode(row))continue;const line=visible.find(l=>l.id===Number(row.dataset.line));if(!line)continue;
   const text=row.querySelector('.line-text')!;const value=line.privateKey?{text:'••••',map:[0,0,0,0,line.raw.length]}:redactWithMap(line.raw);const prefix=line.kind==='cmd'?2:0;
   const offset=(node:Node,n:number)=>{const r=document.createRange();r.selectNodeContents(text);try{r.setEnd(node,n);return Math.max(0,Math.min(value.text.length,r.toString().length-prefix));}catch{return 0;}};
   const start=row.contains(range.startContainer)?offset(range.startContainer,range.startOffset):0;
   const end=row.contains(range.endContainer)?offset(range.endContainer,range.endOffset):value.text.length;
   parts.push((line.kind==='cmd'&&start===0?'$ ':'')+line.raw.slice(value.map[start]??0,value.map[end]??line.raw.length));
  }
  if(parts.length){event.clipboardData.setData('text/plain',parts.join('\n'));event.preventDefault();}
 };
 return <>
  <div className="console-hud"><span className="hud-corner"/><span id="term-focus">{focus?`${focus} · 当前服务器`:'all · 全部服务器'}</span>{focus&&<button className="text-button" id="focus-clear" onClick={onClear}>显示全部</button>}<span className="term-state">{paused?'滚动已暂停':'LIVE / READ ONLY'}</span></div>
  <div id="term" className="term" ref={ref} role="log" aria-label="命令与输出流" tabIndex={0} onCopy={copySelection} onMouseEnter={()=>{hover.current=true;setPaused(true);}} onMouseLeave={()=>{hover.current=false;setPaused(!pinned.current);}} onScroll={scroll}>
   {visible.map(line=><TerminalRow key={line.id} line={line} effects={effects}/>)}
  </div>
  {!visible.length&&<div className="term-empty" id="term-empty"><span>等待第一条请求</span><small>命令、输出和文件传输会在这里汇合。</small></div>}
  <div className="prompt-history" id="prompt-history">{requests.filter(r=>!focus||r.server_id===focus).slice(0,5).reverse().map((r,i,a)=><button key={r.request_id} className={`ph ${i===a.length-1?'latest':''} ${r.status==='pending_approval'?'pending':''}`} style={{opacity:.28+.72*(i+1)/a.length}} onClick={()=>onRequest(r.request_id)}><span className="gt">&gt;</span><span className="ph-cmd"><DisplayText text={r.command_preview}/></span>{i===a.length-1&&<i className="caret" aria-hidden="true"/>}<small>{r.status==='pending_approval'?'待审批':r.server_label}</small></button>)}</div>
 </>;
}
