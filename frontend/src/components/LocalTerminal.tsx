import {useCallback,useEffect,useRef,useState} from 'react';
import {Terminal as XTerm} from '@xterm/xterm';
import {FitAddon} from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import {api,copy} from '../api';
import type {TerminalInfo} from '../types';
// A local PowerShell for the person at this desk. It talks only to the WebView bridge; MCP callers cannot reach it.
interface Tab {key:number;running:boolean;exit:number|null;error:string}
const FONT='"Cascadia Mono","Cascadia Code",Consolas,"Microsoft YaHei UI","Microsoft YaHei",monospace';
const THEME={background:'#07090c',foreground:'#d7dde0',cursor:'#9fd8ff',cursorAccent:'#07090c',selectionBackground:'#9fd8ff44',
 black:'#0c1117',red:'#ff5c7a',green:'#7ee2a8',yellow:'#ffb547',blue:'#6fb6ff',magenta:'#c49bff',cyan:'#6fe3e3',white:'#d7dde0',
 brightBlack:'#6e7a85',brightRed:'#ff8fa3',brightGreen:'#a8f0c6',brightYellow:'#ffd08a',brightBlue:'#9fd8ff',brightMagenta:'#dcc2ff',brightCyan:'#a6f2f2',brightWhite:'#f4f2ec'};
const MAX_TABS=4,MIN_HEIGHT=150;
const message=(e:unknown)=>e instanceof Error?e.message:String(e);
const sleep=(ms:number)=>new Promise(r=>setTimeout(r,ms));
function TerminalView({tabKey,info,active,shown,scale,onState}:{tabKey:number;info:TerminalInfo;active:boolean;shown:boolean;scale:number;onState:(key:number,patch:Partial<Tab>)=>void}){
 const host=useRef<HTMLDivElement>(null),term=useRef<XTerm|null>(null),fit=useRef<FitAddon|null>(null),visible=useRef(shown&&active);
 visible.current=shown&&active;
 useEffect(()=>{
  const t=new XTerm({fontFamily:FONT,fontSize:Math.round(13*scale),lineHeight:1.15,cursorBlink:true,scrollback:5000,theme:THEME,
   linkHandler:null,windowsPty:{backend:'conpty',buildNumber:info.build},rescaleOverlappingGlyphs:true});
  const f=new FitAddon();t.loadAddon(f);t.open(host.current!);term.current=t;fit.current=f;
  let alive=true,id:string|null=null,offset=0,pending='',writing=false,resizeTimer:ReturnType<typeof setTimeout>|undefined;
  // One write in flight keeps keystrokes ordered; anything typed meanwhile goes out as one batch.
  const flush=async()=>{
   if(writing||!pending||!id)return;writing=true;const data=pending;pending='';
   try{await api('terminal_write',id,data);}catch{/* the read loop reports the exit */}finally{writing=false;if(pending)void flush();}
  };
  const send=(data:string)=>{if(!id)return;pending+=data;void flush();};
  const pump=async()=>{
   while(alive&&id){
    let chunk;
    try{chunk=await api('terminal_read',id,offset);}catch(e){if(alive){t.write(`\r\n\x1b[31m${message(e)}\x1b[0m\r\n`);onState(tabKey,{running:false,error:message(e)});}return;}
    if(!alive)return;
    if(chunk.skipped)t.write(`\r\n\x1b[90m[早期输出已省略 ${chunk.skipped} 个字符]\x1b[0m\r\n`);
    if(chunk.data)await new Promise<void>(resolve=>t.write(chunk.data,resolve));
    offset=chunk.next;
    if(!chunk.running&&!chunk.more){
     t.write(`\r\n\x1b[90m[${info.shell} 已退出${chunk.exit_code!==null?' · 代码 '+chunk.exit_code:''}]\x1b[0m\r\n`);
     onState(tabKey,{running:false,exit:chunk.exit_code});return;
    }
    // The read already waits for output; a hidden view just checks back less often.
    if(!chunk.data&&!visible.current)await sleep(700);
   }
  };
  t.attachCustomKeyEventHandler(e=>{
   if(e.type!=='keydown'||!e.ctrlKey||e.altKey||e.metaKey)return true;
   const key=e.key.toLowerCase();
   // Ctrl+C copies only while text is selected, otherwise it interrupts like any console.
   if(key==='c'&&(e.shiftKey||t.hasSelection())){const text=t.getSelection();t.clearSelection();if(text)void copy(text).finally(()=>t.focus());e.preventDefault();return false;}
   if(key==='v')return false;  // the browser's paste event reaches xterm, with bracketed paste
   if(e.code==='Backquote')return false;  // the app toggles the dock
   return true;
  });
  t.onData(send);t.onBinary(send);
  t.onResize(({cols,rows})=>{clearTimeout(resizeTimer);resizeTimer=setTimeout(()=>{if(id&&alive)void api('terminal_resize',id,cols,rows).catch(()=>{});},80);});
  const refit=()=>{if(host.current?.offsetParent)try{f.fit();}catch{/* not laid out yet */}};
  const observer=new ResizeObserver(refit);observer.observe(host.current!);
  (async()=>{
   refit();
   try{
    const session=await api('terminal_open',Math.max(2,t.cols),Math.max(1,t.rows));
    if(!alive){void api('terminal_close',session.id).catch(()=>{});return;}
    id=session.id;onState(tabKey,{running:true});void pump();
   }catch(e){if(alive){t.write(`\x1b[31m${message(e)}\x1b[0m\r\n`);onState(tabKey,{running:false,error:message(e)});}}
  })();
  return()=>{alive=false;clearTimeout(resizeTimer);observer.disconnect();if(id)void api('terminal_close',id).catch(()=>{});t.dispose();term.current=fit.current=null;};
 // A view owns one shell session for its lifetime; scale and visibility are applied below.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 },[]);
 useEffect(()=>{const t=term.current;if(!t)return;t.options.fontSize=Math.round(13*scale);if(host.current?.offsetParent)try{fit.current?.fit();}catch{/* hidden */}},[scale]);
 useEffect(()=>{if(!shown||!active)return;const frame=requestAnimationFrame(()=>{try{fit.current?.fit();}catch{/* hidden */}term.current?.focus();});return()=>cancelAnimationFrame(frame);},[shown,active]);
 const contextCopy=(e:React.MouseEvent)=>{const t=term.current;if(!t?.hasSelection())return;e.preventDefault();const text=t.getSelection();t.clearSelection();void copy(text).finally(()=>t.focus());};
 return <div className="dock-view local-terminal" ref={host} hidden={!active} role="tabpanel" id={'terminal-panel-'+tabKey} aria-labelledby={'terminal-tab-'+tabKey} onContextMenu={contextCopy}/>;
}
export function LocalTerminalDock({open,onHide,scale}:{open:boolean;onHide:()=>void;scale:number}){
 const [info,setInfo]=useState<TerminalInfo|null>(null),[tabs,setTabs]=useState<Tab[]>([]),[active,setActive]=useState(0),[height,setHeight]=useState(()=>Math.round(Math.min(340,Math.max(MIN_HEIGHT,innerHeight*.36))));
 const next=useRef(1),dock=useRef<HTMLElement>(null);
 useEffect(()=>{if(open&&!info)api('terminal_info').then(setInfo,e=>setInfo({available:false,shell:'',build:0,reason:message(e)}));},[open,info]);
 const add=useCallback(()=>{setTabs(list=>{if(list.length>=MAX_TABS)return list;const key=next.current++;setActive(key);return [...list,{key,running:false,exit:null,error:''}];});},[]);
 useEffect(()=>{if(open&&info?.available&&!tabs.length)add();},[open,info,tabs.length,add]);
 const remove=(key:number)=>{const rest=tabs.filter(t=>t.key!==key);setTabs(rest);if(active===key)setActive(rest.at(-1)?.key??0);if(!rest.length)onHide();};
 const update=useCallback((key:number,patch:Partial<Tab>)=>setTabs(list=>list.map(t=>t.key===key?{...t,...patch}:t)),[]);
 const limit=()=>Math.max(MIN_HEIGHT,(dock.current?.parentElement?.clientHeight||innerHeight)-140);
 const resize=(value:number)=>setHeight(Math.round(Math.min(limit(),Math.max(MIN_HEIGHT,value))));
 const drag=(e:React.PointerEvent<HTMLDivElement>)=>{
  if(e.button!==0)return;e.preventDefault();const start=e.clientY,from=height,handle=e.currentTarget;handle.setPointerCapture(e.pointerId);
  const move=(ev:PointerEvent)=>resize(from+start-ev.clientY),end=()=>{handle.removeEventListener('pointermove',move);handle.removeEventListener('pointerup',end);handle.removeEventListener('pointercancel',end);};
  handle.addEventListener('pointermove',move);handle.addEventListener('pointerup',end);handle.addEventListener('pointercancel',end);
 };
 useEffect(()=>{const keep=()=>setHeight(h=>Math.min(h,limit()));window.addEventListener('resize',keep);return()=>window.removeEventListener('resize',keep);},[]);
 const current=tabs.find(t=>t.key===active);
 return <section className="local-dock" id="local-dock" ref={dock} hidden={!open} style={{height}} aria-label="本地终端">
  <div className="dock-resize" role="separator" aria-orientation="horizontal" aria-label="调整终端高度" aria-valuenow={height} aria-valuemin={MIN_HEIGHT} tabIndex={0} onPointerDown={drag} onKeyDown={e=>{if(e.key==='ArrowUp'||e.key==='ArrowDown'){e.preventDefault();resize(height+(e.key==='ArrowUp'?24:-24));}}}/>
  <div className="dock-head">
   <span className="dock-title">本地终端</span>
   <div className="dock-tabs" role="tablist" aria-label="终端会话">{tabs.map((t,i)=><span key={t.key} className={'dock-tab '+(t.key===active?'active ':'')+(t.running?'':'ended')}>
    <button role="tab" id={'terminal-tab-'+t.key} aria-selected={t.key===active} aria-controls={'terminal-panel-'+t.key} onClick={()=>setActive(t.key)}><i className={'status-dot '+(t.running?'live':'')}/>{info?.shell.replace(/ \(pwsh\)$/,'')||'PowerShell'} {i+1}</button>
    <button className="dock-tab-close" onClick={()=>remove(t.key)} aria-label={`关闭终端 ${i+1}`} title="结束并关闭">×</button>
   </span>)}</div>
   <button className="icon-button dock-add" id="terminal-new" onClick={add} disabled={!info?.available||tabs.length>=MAX_TABS} aria-label="新建终端" title={tabs.length>=MAX_TABS?`最多 ${MAX_TABS} 个终端`:'新建终端'}>＋</button>
   <span className="dock-note">{current&&!current.running&&current.exit!==null?'已退出':info?.shell?'本机 · 不经 MCP':''}</span>
   <button className="icon-button" id="terminal-hide" onClick={onHide} aria-label="隐藏终端" title="隐藏（会话保留） Ctrl+`">⌄</button>
  </div>
  <div className="dock-body">
   {info&&!info.available&&<p className="dock-empty" id="terminal-unavailable">{info.reason}</p>}
   {info?.available&&tabs.map(t=><TerminalView key={t.key} tabKey={t.key} info={info} active={t.key===active} shown={open} scale={scale} onState={update}/>)}
  </div>
 </section>;
}
