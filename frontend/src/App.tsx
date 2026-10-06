import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {api} from './api';
import {connectionOrbits,orbitTitle,softwareVersion} from './connection';
import {OrbitPanel} from './components/OrbitPanel';
import {useDesktop} from './useDesktop';
import {elapsed,isLocal,risk,stamp,targetLabel} from './utils';
import {Scene,nodePosition,nodeState} from './components/Scene';
import {Gate,useHoldApproval} from './components/Gate';
import {Terminal} from './components/Terminal';
import {LinkBar} from './components/LinkBar';
import {Connections,Files,Requests,Sessions} from './components/WorkDrawers';
import {Settings,Tunnel} from './components/ConfigDrawers';
import {ModalHost,PromptDialog} from './components/Dialogs';
import {DisplayText} from './components/Text';
import {LocalTerminalDock} from './components/LocalTerminal';
import {AppMark,WindowControls,useWindowFrame} from './components/TitleBar';
import type {ContextMenu,Drawer,Effects,Modal,Snapshot} from './types';
const names:Record<Drawer,string>={requests:'请求记录',connections:'服务器连接',files:'文件与传输',sessions:'受控会话',tunnel:'隧道接入',settings:'运行设置'};
function isEditing(target:EventTarget|null){return target instanceof HTMLElement&&!!target.closest('input,textarea,select,[contenteditable="true"]');}
export default function App(){
 const desktop=useDesktop(),{data,online,error,lines,details,refresh,terrain}=desktop;
 const [drawer,setDrawer]=useState<Drawer|null>(null),[modal,setModal]=useState<Modal>(null),[focus,setFocus]=useState<string|null>(null),[selected,setSelected]=useState<string|null>(null),[gateSelected,setGateSelected]=useState<string|null>(null),[gateOpen,setGateOpen]=useState(false),[palette,setPalette]=useState(false),[query,setQuery]=useState(''),[paletteIndex,setPaletteIndex]=useState(0),[context,setContext]=useState<ContextMenu|null>(null),[effects,setEffects]=useState<Effects>('standard'),[reduced,setReduced]=useState(matchMedia('(prefers-reduced-motion: reduce)').matches),[clock,setClock]=useState(new Date()),[toast,setToast]=useState<{text:string;error:boolean}|null>(null),[leaving,setLeaving]=useState<Record<string,string>>({});
 const toastTimer=useRef<ReturnType<typeof setTimeout>|undefined>(undefined),leaveTimers=useRef<ReturnType<typeof setTimeout>[]>([]),newIds=useRef(new Set<string>()),paletteInput=useRef<HTMLInputElement>(null),drawerRef=useRef<HTMLElement>(null),lastFocus=useRef<HTMLElement|null>(null),scaleInitialized=useRef(false);
 const keyHandler=useRef<(event:KeyboardEvent)=>void>(()=>{}),quickApproving=useRef(false);
 const {frame,windowAction}=useWindowFrame(),[dock,setDock]=useState(false);
 const effective=reduced&&effects==='standard'?'low':effects;
 const notify=useCallback((text:string,error=false)=>{setToast({text,error});clearTimeout(toastTimer.current);toastTimer.current=setTimeout(()=>setToast(null),error?7000:3200);},[]);
 const report=useCallback((e:unknown)=>notify(e instanceof Error?e.message:String(e),true),[notify]);
 const act=useCallback(async(job:()=>Promise<unknown>,message?:string)=>{try{await job();if(message)notify(message);await refresh();}catch(e){report(e);}},[refresh,notify,report]);
 const openDrawer=useCallback((page:Drawer|null)=>{setContext(null);setPalette(false);if(page)lastFocus.current=document.activeElement as HTMLElement;setDrawer(page);},[]);
 const onRequest=useCallback((id:string)=>{setSelected(id);openDrawer('requests');},[openDrawer]);
 const onConnect=useCallback((id:string,server:string)=>{setSelected(id);setFocus(server);openDrawer(null);},[openDrawer]);
 const orbits=useMemo(()=>connectionOrbits(data?.requests||[],details),[data?.requests,details]);
 const orbit=(focus?orbits[focus]:undefined)||Object.values(orbits).find(o=>o.outcome==='active')||Object.values(orbits)[0];
 const orbitServer=data?.servers.find(s=>s.id===orbit?.request.server_id);
 const animateLeave=useCallback((id:string,kind:string)=>{setLeaving(prev=>({...prev,[id]:kind}));leaveTimers.current.push(setTimeout(()=>setLeaving(prev=>{const next={...prev};delete next[id];return next;}),450));},[]);
 const approved=useCallback(async(id:string)=>{animateLeave(id,'approved');notify('请求已批准');await refresh();},[animateLeave,notify,refresh]);
 const hold=useHoldApproval(approved,report);
 const reject=useCallback((id:string)=>{hold.stop();void act(async()=>{await api('reject',id);animateLeave(id,'leaving');},'请求已拒绝');},[act,animateLeave,hold.stop]);
 const pending=data?.requests.filter(r=>r.status==='pending_approval')||[];
 const changeEffects=useCallback((next:Effects)=>{if(!data)return;const previous=effects;setEffects(next);void act(async()=>{try{await api('save_settings',{ui:{effects:next,motion_enabled:next!=='off',scale_percent:data.settings.scale_percent}});}catch(e){setEffects(previous);throw e;}});},[data,effects,act]);
 useEffect(()=>{const media=matchMedia('(prefers-reduced-motion: reduce)'),handle=()=>setReduced(media.matches);media.addEventListener('change',handle);const timer=setInterval(()=>setClock(new Date()),1000);return()=>{media.removeEventListener('change',handle);clearInterval(timer);clearTimeout(toastTimer.current);leaveTimers.current.forEach(clearTimeout);};},[]);
 useEffect(()=>{if(data){setEffects(data.settings.effects||(data.settings.motion_enabled?'standard':'off'));if(!scaleInitialized.current){document.documentElement.style.setProperty('--font-scale',String(data.settings.scale_percent/100));scaleInitialized.current=true;}}},[data?.settings.effects,data?.settings.motion_enabled]);
 useEffect(()=>{document.body.className=`fx-${effective} ${effective!=='off'?'fx-on':''} ${reduced?'reduced-motion':''} ${pending.length?'has-pending':''}`;},[effective,reduced,pending.length]);
 useEffect(()=>{const ids=new Set(pending.map(r=>r.request_id));if([...ids].some(id=>!newIds.current.has(id))&&innerWidth<1280)setGateOpen(true);newIds.current=ids;if(!ids.has(gateSelected||''))setGateSelected(pending[0]?.request_id||null);if(hold.holding&&!ids.has(hold.holding.id))hold.stop();},[pending.map(r=>r.request_id).join('|')]);
 useEffect(()=>{if(hold.holding&&hold.holding.id!==gateSelected)hold.stop();},[gateSelected]);
 useEffect(()=>{if(focus&&data&&!data.servers.some(s=>s.id===focus))setFocus(null);},[focus,data?.servers]);
 useEffect(()=>{if(palette){hold.stop();setQuery('');setPaletteIndex(0);requestAnimationFrame(()=>paletteInput.current?.focus());}},[palette]);
 useEffect(()=>{if(drawer){hold.stop();drawerRef.current?.querySelector<HTMLElement>('button')?.focus();}else lastFocus.current?.isConnected&&lastFocus.current.focus({preventScroll:true});},[drawer]);
 useEffect(()=>{if(modal||data?.prompt)hold.stop();},[modal,data?.prompt?.id]);
 useEffect(()=>{const close=()=>setContext(null);window.addEventListener('click',close);window.addEventListener('resize',close);return()=>{window.removeEventListener('click',close);window.removeEventListener('resize',close);};},[]);
 const onGate=useCallback((id:string)=>{setGateSelected(id);setDrawer(null);setGateOpen(true);},[]);
 const retireToTerrain=useCallback((rows:string[])=>{terrain.current=[...terrain.current,...rows].slice(-80);},[terrain]);
 const upload=useCallback(()=>void act(async()=>{const transfer=await api('prepare_upload');if(transfer)setModal({kind:'upload',transfer});}),[act]);
 const commands=useMemo(()=>{
  const items:{id:string;label:string;hint:string;group:string;run:()=>void}[]=[
   {id:'new',label:'新建连接',hint:'SSH config / known_hosts',group:'操作',run:()=>setModal({kind:'connection'})},
   {id:'files',label:'浏览文件',hint:focus||'选择服务器',group:'操作',run:()=>openDrawer('files')},
   {id:'upload',label:'上传文件',hint:'本地选择 → 逐次审批',group:'操作',run:upload},
   {id:'sessions',label:'会话上下文',hint:'目录与环境变量',group:'操作',run:()=>openDrawer('sessions')},
   {id:'tunnel',label:data?.tunnel.running?'停止隧道':'启动隧道',hint:data?.tunnel.running?'停止本地客户端':'打开运行密钥输入',group:'操作',run:()=>data?.tunnel.running?void act(()=>api('stop_tunnel')):openDrawer('tunnel')},
   {id:'effects',label:'切换特效强度',hint:{off:'关 → 低',low:'低 → 标准',standard:'标准 → 关'}[effects],group:'操作',run:()=>changeEffects(effects==='off'?'low':effects==='low'?'standard':'off')},
   {id:'history',label:'搜索历史请求',hint:'当前进程',group:'操作',run:()=>openDrawer('requests')},
   {id:'settings',label:'运行设置',hint:'显示、执行限制、MCP',group:'操作',run:()=>openDrawer('settings')},
   {id:'terminal',label:dock?'隐藏本地终端':'打开本地终端',hint:'PowerShell · Ctrl+`',group:'操作',run:()=>setDock(d=>!d)},
   {id:'new-local',label:'新建本机工作区',hint:'限定目录 · MCP 文件与 PowerShell',group:'操作',run:()=>setModal({kind:'connection',local:true})},
   {id:'all',label:'显示全部服务器',hint:'清除终端过滤',group:'服务器',run:()=>setFocus(null)}
  ];for(const s of data?.servers||[])items.push({id:'server-'+s.id,label:s.label,hint:targetLabel(s),group:'服务器',run:()=>setFocus(s.id)});
  if(query.trim())for(const r of data?.requests||[])items.push({id:r.request_id,label:r.command_preview,hint:r.server_label+' · '+stamp(r.created_at),group:'历史请求',run:()=>onRequest(r.request_id)});
  return items.filter(i=>(i.label+' '+i.hint).toLowerCase().includes(query.toLowerCase())).slice(0,60);
 },[data,query,focus,effects,dock,act,changeEffects,openDrawer,onRequest,upload]);
 useEffect(()=>setPaletteIndex(0),[query]);
 const chosen=Math.min(paletteIndex,Math.max(0,commands.length-1));
 useEffect(()=>{if(palette)document.getElementById('palette-option-'+chosen)?.scrollIntoView({block:'nearest'});},[chosen,palette]);
 // A on the main view approves the top pending request at once; the approve button keeps its 0.5 s hold.
 const approveTop=async()=>{
  const top=pending.find(r=>!leaving[r.request_id]);
  if(!top||quickApproving.current||hold.busy)return;
  if(!details[top.request_id]){notify('正在读取完整请求，请稍后再按 A',true);return;}
  if(top.operation!=='request_auto_approval'&&data?.requests.some(r=>r.status==='running')){notify('已有命令正在运行；完成后再批准下一条',true);return;}
  quickApproving.current=true;hold.stop();setGateSelected(top.request_id);
  try{const review=await api('begin_review',top.request_id);await api('approve',top.request_id,review.ticket,true);await approved(top.request_id);}
  catch(e){report(e);}finally{quickApproving.current=false;}
 };
 keyHandler.current=(e:KeyboardEvent)=>{
   if(e.defaultPrevented)return;
   if(e.ctrlKey&&!e.altKey&&!e.metaKey&&e.code==='Backquote'){if(data?.prompt||modal)return;e.preventDefault();setPalette(false);setDock(d=>!d);return;}
   // Keys typed into the local shell belong to the shell, not to app shortcuts.
   if(e.target instanceof Element&&e.target.closest('.local-terminal'))return;
   if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){if(data?.prompt)return;e.preventDefault();setPalette(p=>!p);return;}
   if(e.key==='Escape'){hold.stop();setContext(null);if(palette)setPalette(false);else if(!modal&&!data?.prompt&&drawer)openDrawer(null);return;}
   if(palette){if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();setPaletteIndex(i=>(i+(e.key==='ArrowDown'?1:-1)+Math.max(1,commands.length))%Math.max(1,commands.length));}else if(e.key==='Enter'){e.preventDefault();commands[chosen]?.run();setPalette(false);}return;}
   if(isEditing(e.target)||modal||data?.prompt||drawer||e.ctrlKey||e.altKey||e.metaKey)return;
   const k=e.key.toLowerCase(),index=pending.findIndex(r=>r.request_id===gateSelected);
   if(k==='j'||k==='k'){e.preventDefault();hold.stop();const next=pending[(Math.max(0,index)+(k==='j'?1:-1)+pending.length)%pending.length];if(next){setGateSelected(next.request_id);setGateOpen(true);}}
   else if(k==='a'){e.preventDefault();if(!e.repeat)void approveTop();}
   else if(k==='r'&&!e.repeat&&gateSelected){e.preventDefault();reject(gateSelected);}
   else if(e.key==='Enter'&&gateSelected){e.preventDefault();onRequest(gateSelected);}
  };
 useEffect(()=>{const listener=(e:KeyboardEvent)=>keyHandler.current(e);window.addEventListener('keydown',listener);return()=>window.removeEventListener('keydown',listener);},[]);
 useEffect(()=>{window.SSHUI={refresh,go:(name:string)=>{if(name in names)openDrawer(name as Drawer);},diagnostics:()=>({lineCount:lines.length,terrainRows:terrain.current.length,effects:effective,focus,react:true})};return()=>{delete window.SSHUI;};},[refresh,openDrawer,lines.length,terrain,effective,focus]);
 const config=(page:Drawer)=>openDrawer(page);const focusServer=data?.servers.find(s=>s.id===focus);
 const hasDestructive=pending.some(r=>risk(details[r.request_id]||r)==='destructive');
 return <>
  <Scene servers={data?.servers||[]} requests={data?.requests||[]} focus={focus} effects={effective} online={online&&!!data?.mcp.running} terrain={terrain} orbits={orbits} orbitServer={orbitServer?.id} reduced={reduced}/><div className="vignette"/><div className={'edge-glow '+(hasDestructive?'danger':'')}/>
  <div className="app"><header className={'linkbar'+(frame.custom_frame?' titlebar':'')} id="titlebar"><div className="hud-id"><AppMark/><b>SSH GATE</b><span id="hud-nodes">{data?.servers.length||0} servers</span><span id="app-version">{data?'v'+data.version:'—'}</span></div><LinkBar data={data} animate={effective!=='off'} onOpen={config}/><div className="hud-right"><button className="hud-key" id="palette-open" onClick={()=>setPalette(true)} aria-label="打开命令面板">Ctrl K</button><span className="bridge"><i className={'status-dot '+(online?'live':'warning')} id="bridge-dot"/><span id="bridge-label">{online?'本地应用已连接':'等待本地应用'}</span></span><span className="timecode" id="clock">{clock.toLocaleTimeString('zh-CN',{hour12:false})}</span></div>{frame.custom_frame&&<WindowControls maximized={frame.maximized} onAction={windowAction}/>}</header>
  {(error||data?.mcp.error||!data)&&<div className="notice" id="service-notice" role="status">{error||data?.mcp.error||'正在连接本地 WebView。请使用 Start-App.cmd 启动。'}</div>}
  <main className="stage" id="main"><div className="stage-main"><section className={"console "+(orbit&&orbitServer?"has-orbit":"")} aria-label="实时终端（只读）"><Terminal lines={lines} focus={focus} effects={effective==='standard'} requests={data?.requests||[]} onRequest={onRequest} onClear={()=>setFocus(null)} onTerrain={retireToTerrain}/>{orbit&&orbitServer&&<OrbitPanel key={orbit.request.request_id} orbit={orbit} server={orbitServer} now={clock.getTime()} online={online} onDetail={onRequest}/>}<div className="node-layer" id="node-layer">{data?.servers.map((s,i)=>{const p=nodePosition(i,data.servers.length),state=nodeState(s,data.requests),o=orbits[s.id],plate=s.id===orbitServer?.id&&o?.context.role==='target'?softwareVersion(o.metadata.server_version):'';return <button key={s.id} data-server={s.id} className={`node ${state} ${s.id===focus?'focused':''}`} style={{left:`calc(${p.x*100}% + ${30-56*p.x}px)`,top:p.y*100+'%'}} onClick={()=>setFocus(prev=>prev===s.id?null:s.id)} onContextMenu={e=>{e.preventDefault();hold.stop();setContext({server:s.id,x:Math.min(e.clientX,innerWidth-190),y:Math.min(e.clientY,innerHeight-230)});}} aria-label={`聚焦 ${s.label}`}><span>{s.label}</span><span className="nlat">· {o?.outcome==='active'?orbitTitle(o):state==='running'?'执行中':state==='pending'?'待审批':state==='down'?'断连':s.connected?(o?.outcome==='connected'?`已连接 · ${(o.last.elapsed_ms/1000).toFixed(2)}s`:'已连接'):'未登录'}</span>{plate&&<span className="nplate">{plate}</span>}</button>;})}{data&&!data.servers.length&&<button className="new-node" onClick={()=>setModal({kind:'connection'})}>＋ 新建连接<small>从 SSH config 或已知主机开始</small></button>}</div></section><LocalTerminalDock open={dock} onHide={()=>setDock(false)} scale={(data?.settings.scale_percent||100)/100}/></div><Gate requests={data?.requests||[]} details={details} selected={gateSelected} onSelect={setGateSelected} open={gateOpen} onToggle={setGateOpen} onReject={reject} onDetail={onRequest} hold={hold} leaving={leaving}/></main>
  <footer className="statusbar"><span className="footer-state"><i className={'status-dot '+(online?'live':'warning')} id="footer-dot"/><span id="footer-state">{focusServer?focusServer.label+' · ':''}{pending.length?pending.length+' 条请求等待审批':orbit?.outcome==='active'?'SSH · '+orbitTitle(orbit):data?.requests.some(r=>r.status==='running')?'命令执行中 · 接收输出':online?'本地服务运行中':'等待本地应用'}</span></span><span id="footer-requests">{data?.requests.length||0} / 200 REQUESTS</span><span id="footer-uptime">UPTIME {elapsed(data?.uptime_seconds||0)}</span><button className="status-toggle" id="readonly-quick" disabled={!data} onClick={()=>data&&void act(()=>api('set_readonly',!data.settings.auto_allow_readonly))}>只读自动放行 <b>{data?.settings.auto_allow_readonly?'开':'关'}</b></button><button className="status-toggle" id="effects-quick" onClick={()=>changeEffects(effects==='off'?'low':effects==='low'?'standard':'off')}>特效 <b>{{off:'关',low:'低',standard:'标准'}[effective]}</b></button><button className="status-toggle" onClick={()=>openDrawer('requests')}>请求记录</button><button className="status-toggle" id="terminal-toggle" aria-pressed={dock} title="本地 PowerShell · Ctrl+`" onClick={()=>setDock(d=>!d)}>终端 <b>{dock?'开':'关'}</b></button></footer></div>
  {drawer&&data&&<aside className="drawer" id="drawer" ref={drawerRef} aria-label={names[drawer]} onKeyDown={e=>{if(e.key==='Tab'){const elements=[...e.currentTarget.querySelectorAll<HTMLElement>('button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex="0"]')].filter(el=>el.offsetParent!==null);const first=elements[0],last=elements.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last?.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first?.focus();}}}}><div className="drawer-head"><div><div className="eyebrow">WORKSPACE</div><h2 id="drawer-title">{names[drawer]}</h2></div><nav className="drawer-tabs" aria-label="抽屉分区">{(Object.keys(names) as Drawer[]).map(page=><button key={page} data-drawer={page} className={drawer===page?'active':''} onClick={()=>openDrawer(page)}>{page==='connections'?'连接':page==='requests'?'请求':page==='files'?'文件':page==='sessions'?'会话':page==='tunnel'?'隧道':'设置'}</button>)}</nav><button className="icon-button" id="drawer-close" onClick={()=>openDrawer(null)} aria-label="关闭抽屉">×</button></div><div className="drawer-body">{drawer==='connections'&&<Connections data={data} act={act} openModal={setModal} onRequest={onRequest} onConnect={onConnect}/>} {drawer==='files'&&<Files data={data} act={act} openModal={setModal} onRequest={onRequest} preferred={focus}/>} {drawer==='sessions'&&<Sessions data={data} act={act} openModal={setModal} onRequest={onRequest}/>} {drawer==='requests'&&<Requests data={data} act={act} openModal={setModal} onRequest={onRequest} selected={selected} onGate={onGate}/>} {drawer==='tunnel'&&<Tunnel data={data} act={act}/>} {drawer==='settings'&&<Settings data={data} act={act} effects={effects} onEffects={changeEffects}/>}</div></aside>}
  {context&&data&&<div className="ctx-menu" id="ctx-menu" style={{left:context.x,top:context.y}} role="menu"><div className="ctx-title">{data.servers.find(s=>s.id===context.server)?.label}</div><button role="menuitem" onClick={()=>{const server=context.server;void act(async()=>onConnect((await api('test_connection',server)).request_id,server));}}>连接 / 测试</button><button role="menuitem" onClick={()=>{setFocus(context.server);openDrawer('files');}}>打开文件</button><button role="menuitem" onClick={()=>{setFocus(context.server);openDrawer('sessions');}}>会话上下文</button>{isLocal(data.servers.find(s=>s.id===context.server))?<button role="menuitem" onClick={()=>setModal({kind:'connection',server:context.server})}>编辑工作区</button>:<><button role="menuitem" onClick={()=>setModal({kind:'connection',server:context.server,policy:true})}>服务器策略</button><button role="menuitem" onClick={()=>setModal({kind:'confirm',title:'断开此连接？',text:'连接配置会保留，下次执行重新认证。',run:()=>api('disconnect_connection',context.server)})}>断开连接</button></>}</div>}
  {palette&&<div className="palette" id="palette" role="dialog" aria-modal="true" aria-label="命令面板" onPointerDown={e=>{if(e.target===e.currentTarget)setPalette(false);}}><div className="palette-box"><label className="palette-input"><span>⌕</span><input id="palette-input" ref={paletteInput} placeholder="搜索命令、服务器或历史请求" value={query} onChange={e=>{setQuery(e.target.value);setPaletteIndex(0);}} aria-label="搜索命令" role="combobox" aria-expanded="true" aria-controls="palette-list" aria-activedescendant={'palette-option-'+chosen}/><button className="text-button" onClick={()=>setPalette(false)}>Esc</button></label><div className="palette-list" id="palette-list" role="listbox">{commands.length?commands.map((item,i)=><div key={item.id}>{(i===0||commands[i-1].group!==item.group)&&<div className="pi-group">{item.group}</div>}<button id={'palette-option-'+i} className={'pi '+(i===chosen?'sel':'')} role="option" aria-selected={i===chosen} onPointerMove={()=>setPaletteIndex(i)} onClick={()=>{setPalette(false);item.run();}}><span><DisplayText text={item.label}/></span><small>{item.hint}</small></button></div>):<div className="empty-state">没有匹配项。</div>}</div><div className="palette-foot">↑↓ 选择 · Enter 执行 · Esc 关闭</div></div></div>}
  {data?.prompt?<PromptDialog key={data.prompt.id} prompt={data.prompt} onRefresh={refresh} onError={report}/>:modal&&data?<ModalHost key={JSON.stringify({kind:modal.kind,id:'id' in modal?modal.id:undefined,server:'server' in modal?modal.server:undefined})} modal={modal} data={data} onClose={()=>setModal(null)} onRefresh={refresh} onRequest={onRequest} onConnect={onConnect}/>:null}
  {toast&&<div id="toast" className={'toast '+(toast.error?'error':'')} role="status">{toast.text}</div>}
 </>;
}
