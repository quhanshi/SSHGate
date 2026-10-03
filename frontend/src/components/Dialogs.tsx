import {useEffect,useRef,useState} from 'react';
import {api} from '../api';
import type {Modal,Profiles,Prompt,Route,Session,Snapshot} from '../types';
function value(form:HTMLFormElement,name:string){return (form.elements.namedItem(name) as HTMLInputElement|null)?.value||'';}
function checked(form:HTMLFormElement,name:string){return !!(form.elements.namedItem(name) as HTMLInputElement|null)?.checked;}
export function Dialog({title,children,onClose,wide=false}:{title:string;children:React.ReactNode;onClose:()=>void;wide?:boolean}){
 const ref=useRef<HTMLDialogElement>(null),callback=useRef(onClose);callback.current=onClose;
 useEffect(()=>{const previous=document.activeElement as HTMLElement|null;ref.current?.showModal();return()=>{ref.current?.close();if(previous?.isConnected)previous.focus({preventScroll:true});};},[]);
 return <dialog id="modal" ref={ref} className={wide?'wide':''} aria-labelledby="modal-title" onCancel={e=>{e.preventDefault();callback.current();}}><div className="modal-heading"><div><div className="eyebrow">LOCAL CONTROL</div><h2 id="modal-title">{title}</h2></div><button className="icon-button" onClick={onClose} aria-label="关闭对话框">×</button></div>{children}</dialog>;
}
export function ConnectionFields({data,id,policy}:{data:Snapshot;id?:string;policy?:boolean}){
 const existing=data.servers.find(s=>s.id===id),target=existing?.ssh_target||'',at=target.lastIndexOf('@');
 const [profiles,setProfiles]=useState<Profiles>({profiles:[]}),[known,setKnown]=useState<{host:string;port:number}[]>([]),[route,setRoute]=useState<Route|null>(null),[error,setError]=useState('');
 const root=useRef<HTMLDivElement>(null);let number=1;while(data.servers.some(s=>s.id==='server'+number))number++;
 const form=()=>root.current!.closest('form')!;
 const set=(name:string,v:string)=>{const el=form().elements.namedItem(name) as HTMLInputElement|null;if(el)el.value=v;};
 const load=async()=>{try{setProfiles(await api('ssh_profiles',value(form(),'ssh_config_file')));setError('');}catch(e){setError(String(e));}};
 useEffect(()=>{let alive=true;void Promise.all([api('ssh_profiles',existing?.ssh_config_file||''),api('known_hosts')]).then(([p,k])=>{if(alive){setProfiles(p);setKnown(k);}}).catch(e=>{if(alive)setError(String(e));});return()=>{alive=false;};},[existing?.ssh_config_file]);
 const apply=(alias:string)=>{set('host',alias);set('user','');set('port','');set('identity_file','');if(!value(form(),'label'))set('label',alias);setRoute(null);};
 const [defaults,setDefaults]=useState(!existing?.auto_categories?.length);
 const pick=async(purpose:string,name:string)=>{try{const path=await api('choose_file',purpose);if(path){set(name,path);if(purpose==='ssh_config')await load();}}catch(e){setError(String(e));}};
 return <div ref={root}>
  <p className="modal-intro">优先选择 SSH config 中的 Host，复用用户名、密钥和跳板路由。</p>
  <label>SSH 配置中的 Host<select id="ssh-profile-select" defaultValue={!at&&target&&profiles.profiles.some(p=>p.alias===target)?target:''} onChange={e=>e.target.value&&apply(e.target.value)}><option value="">选择已有 SSH 配置</option>{profiles.profiles.map(p=><option key={p.alias} value={p.alias}>{p.alias}</option>)}</select></label>
  <p className="inline-help">{profiles.error||profiles.config_path||'暂未找到具体 Host，可手动输入。'}</p>
  <label>备用：known_hosts 地址<select id="known-select" defaultValue="" onChange={e=>{const k=known[Number(e.target.value)];if(e.target.value&&k){if(profiles.profiles.some(p=>p.alias===k.host))apply(k.host);else{set('host',k.host);set('port',String(k.port));}}}}><option value="">选择已知主机</option>{known.map((k,i)=><option key={i} value={i}>{k.host} : {k.port}</option>)}</select></label>
  <div className="form-grid"><label>连接 ID<input id="conn-id" name="id" defaultValue={existing?.id||'server'+number} readOnly={!!existing} required pattern="[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}"/></label><label>显示名称<input id="conn-label" name="label" defaultValue={existing?.label||''} required autoFocus/></label><label>主机 / SSH 别名<input id="conn-host" name="host" defaultValue={at>=0?target.slice(at+1):target} required/></label><label>服务器用户名<input id="conn-user" name="user" defaultValue={at>=0?target.slice(0,at):''} placeholder="留空读取 SSH 配置"/></label><label>端口<input id="conn-port" name="port" type="number" min="1" max="65535" defaultValue={existing?.port||''} placeholder="SSH 配置 / 22"/></label><label>默认工作目录<input id="conn-cwd" name="default_cwd" defaultValue={existing?.default_cwd||'.'} required/></label></div>
  <label>私钥文件 / 可选<div className="input-with-button"><input id="conn-identity" name="identity_file" defaultValue={existing?.identity_file||''}/><button type="button" className="button" onClick={()=>void pick('identity','identity_file')}>选择</button></div></label>
  <details><summary>指定 SSH 配置文件</summary><div className="input-with-button"><input id="conn-config" name="ssh_config_file" defaultValue={existing?.ssh_config_file||''}/><button type="button" className="button" onClick={()=>void pick('ssh_config','ssh_config_file')}>选择</button></div></details>
  <details open={policy}><summary>此服务器的自动授权类别与目录</summary><label className="check"><input id="policy-default" name="policy_default" type="checkbox" checked={defaults} onChange={e=>setDefaults(e.target.checked)}/>沿用全局只读列表</label><fieldset disabled={defaults}><div className="policy-categories">{[['read_fs','文件读取'],['diagnostics','系统诊断'],['git_read','Git 只读'],['docker_read','Docker 只读'],['python_tests','受信任 pytest']].map(([k,label])=><label className="check" key={k}><input type="checkbox" name="category" value={k} defaultChecked={existing?.auto_categories.includes(k)}/>{label}</label>)}</div><label>自动授权的绝对目录 / 每行一个<textarea id="policy-roots" name="auto_roots" rows={3} defaultValue={existing?.auto_roots.join('\n')||''}/></label></fieldset><p className="inline-help">pytest 授权必须指定目录。未选择类别时全部人工审批。</p></details>
  <div className="button-group"><button type="button" className="button" id="reload-profiles" onClick={()=>void load()}>重新读取 Host</button><button type="button" className="button" id="preview-ssh" onClick={()=>{const f=form(),host=value(f,'host'),user=value(f,'user');void api('preview_connection',{ssh_target:user?user+'@'+host:host,port:value(f,'port')?Number(value(f,'port')):null,identity_file:value(f,'identity_file'),ssh_config_file:value(f,'ssh_config_file')}).then(setRoute).catch(e=>setError(String(e)));}}>预览 SSH 路由</button></div>
  {route&&<div id="ssh-route-preview" className="route-preview"><p>仅解析配置，尚未连接。{route.config_source}</p><ol>{route.route.map((n,i)=><li key={i}>{i<route.route.length-1?'跳板 '+(i+1):'目标'} · {n.host_alias} → {n.username}@{n.hostname}:{n.port}<br/>密钥 {n.identity_files.join(', ')||'本地默认 / agent'} · IdentitiesOnly {n.identities_only?'yes':'no'}{n.proxy_command?' · 本地 ProxyCommand':''}</li>)}</ol></div>}
  {error&&<p className="error">{error}</p>}
 </div>;
}
export function ModalHost({modal,data,onClose,onRefresh,onRequest}:{modal:Exclude<Modal,null>;data:Snapshot;onClose:()=>void;onRefresh:()=>Promise<void>;onRequest:(id:string)=>void}){
 const [busy,setBusy]=useState(false),[error,setError]=useState(''),[session,setSession]=useState<Session|null>(null),formRef=useRef<HTMLFormElement>(null);
 const sessionId=(modal.kind==='session'||modal.kind==='session-command')?modal.id:undefined;
 useEffect(()=>{let alive=true;if(sessionId)void api('session_detail',sessionId).then(s=>{if(alive)setSession(s);}).catch(e=>{if(alive)setError(String(e));});return()=>{alive=false;};},[sessionId]);
 const titles={connection:modal.kind==='connection'&&modal.server?'编辑服务器连接':'新建服务器连接',command:'本地提交命令',upload:'上传到服务器',session:sessionId?'修改会话上下文':'创建受控会话','session-command':'在会话上下文执行',confirm:modal.kind==='confirm'?modal.title:''};
 const serverId=('server' in modal?modal.server:undefined)||data.servers[0]?.id||'';
 const submit=async(event:React.FormEvent<HTMLFormElement>)=>{
  event.preventDefault();if(busy)return;setBusy(true);setError('');const form=event.currentTarget;
  try{
   let request:RequestSummaryLike|null=null;
   if(modal.kind==='connection'){
    const host=value(form,'host').trim(),user=value(form,'user').trim(),defaults=checked(form,'policy_default'),categories=new FormData(form).getAll('category').map(String),roots=value(form,'auto_roots').split(/\r?\n/).map(s=>s.trim()).filter(Boolean);
    if(!defaults&&categories.includes('python_tests')&&!roots.length)throw new Error('自动测试执行必须指定授权目录');
    const id=value(form,'id').trim();await api('save_connection',{id,label:value(form,'label').trim(),ssh_target:user?user+'@'+host:host,default_cwd:value(form,'default_cwd').trim()||'.',port:value(form,'port')?Number(value(form,'port')):null,identity_file:value(form,'identity_file').trim(),ssh_config_file:value(form,'ssh_config_file').trim(),auto_categories:defaults?[]:categories.length?categories:['manual_only'],auto_roots:defaults?[]:roots},!!modal.server);
    if((event.nativeEvent as SubmitEvent).submitter?.getAttribute('value')==='test')request=await api('test_connection',id);
   }else if(modal.kind==='command')request=await api('submit_local',value(form,'server_id'),value(form,'command'),value(form,'reason'),value(form,'cwd'),Number(value(form,'timeout')));
   else if(modal.kind==='upload'){const operation=value(form,'operation');const args:Record<string,unknown>={path:value(form,'path'),transfer_id:modal.transfer.transfer_id};if(operation==='upload_file')args.overwrite=checked(form,'overwrite');request=await api('filesystem',value(form,'server_id'),operation,args);}
   else if(modal.kind==='session'){
    const environment=JSON.parse(value(form,'environment'));if(!environment||Array.isArray(environment)||typeof environment!=='object'||Object.values(environment).some(v=>typeof v!=='string'))throw new Error('环境变量必须是字符串值组成的 JSON 对象');
    const values:Record<string,unknown>={server_id:value(form,'server_id'),cwd:value(form,'cwd'),environment};if(modal.id)values.session_id=modal.id;request=await api('session_action',modal.id?'update':'create',values);
   }else if(modal.kind==='session-command')request=await api('session_action','execute',{session_id:modal.id,command:value(form,'command'),reason:value(form,'reason'),timeout_seconds:Number(value(form,'timeout'))});
   else if(modal.kind==='confirm')await modal.run();
   onClose();await onRefresh();if(request)onRequest(request.request_id);
  }catch(e){setError(e instanceof Error?e.message:String(e));}finally{setBusy(false);}
 };
 const select=<label>服务器<select name="server_id" defaultValue={session?.server_id||serverId} disabled={!!sessionId} required>{data.servers.map(s=><option key={s.id} value={s.id}>{s.label} / {s.ssh_target}</option>)}</select></label>;
 const commands=<><label>执行目的<input id={modal.kind==='command'?'cmd-reason':'session-reason'} name="reason" required defaultValue={modal.kind==='session-command'?'在受控会话中执行命令':''}/></label><label>完整命令<textarea id={modal.kind==='command'?'cmd-script':'session-command'} name="command" rows={6} spellCheck={false} required autoFocus/></label><label>执行时限 / 秒<input name="timeout" type="number" min="1" max={data.settings.max_command_timeout_seconds} defaultValue={300} required/></label></>;
 return <Dialog title={titles[modal.kind]} onClose={()=>{if(!busy)onClose();}} wide><form ref={formRef} onSubmit={submit}>
  <fieldset disabled={busy} className="modal-fields">
   {modal.kind==='connection'&&<ConnectionFields data={data} id={modal.server} policy={modal.policy}/>}
   {modal.kind==='command'&&<>{select}<label>工作目录<input name="cwd" defaultValue={data.servers.find(s=>s.id===serverId)?.default_cwd||'.'} required/></label>{commands}</>}
   {modal.kind==='upload'&&<><p>{modal.transfer.file_name} · {modal.transfer.size_bytes} bytes</p><p className="inline-help">SHA256 {modal.transfer.sha256}</p>{select}<label>模式<select name="operation" id="up-mode"><option value="upload_file">上传为单文件</option><option value="upload_directory">ZIP 解压到新目录</option></select></label><label>远程完整目标路径<input id="up-path" name="path" placeholder="/data/project/patch.zip" required/></label><label className="check"><input id="up-overwrite" name="overwrite" type="checkbox"/>允许覆盖已有普通文件 / 单文件模式</label><p className="inline-help">提交后仍需在闸门核对并批准。</p></>}
   {modal.kind==='session'&&(!sessionId||session)?<div key={session?.revision||0}>{select}<label>工作目录<input id="session-cwd" name="cwd" defaultValue={session?.cwd||data.servers.find(s=>s.id===serverId)?.default_cwd||'.'} required/></label><label>环境变量 / JSON<textarea id="session-env" name="environment" rows={5} defaultValue={JSON.stringify(session?.environment||{},null,2)} required spellCheck={false}/></label><p className="inline-help">修改上下文需要审批；请勿填写密码。</p></div>:null}
   {modal.kind==='session-command'&&<><p>{session?.server_id} · {session?.cwd||'读取上下文…'}</p>{commands}</>}
   {modal.kind==='confirm'&&<p className="modal-intro">{modal.text}</p>}
  </fieldset>
  {error&&<div className="modal-error" id="modal-error" role="alert">{error}</div>}
  <div className="modal-actions"><button type="button" className="button" onClick={onClose} disabled={busy}>取消</button>{modal.kind==='connection'&&<button type="submit" className="button" disabled={busy}>仅保存</button>}<button type="submit" value="test" className="button primary" disabled={busy||(!!sessionId&&!session)}>{busy?'正在处理…':modal.kind==='connection'?'保存并测试':modal.kind==='session'?'提交上下文审批':modal.kind==='upload'?'提交上传审批':modal.kind==='confirm'?'确认':'提交请求'}</button></div>
 </form></Dialog>;
}
interface RequestSummaryLike {request_id:string}
export function PromptDialog({prompt,onRefresh,onError}:{prompt:Prompt;onRefresh:()=>Promise<void>;onError:(e:unknown)=>void}){
 const [busy,setBusy]=useState(false),[visible,setVisible]=useState(false),[error,setError]=useState('');const input=useRef<HTMLInputElement>(null);
 const answer=async(response:unknown)=>{if(busy)return;setBusy(true);setError('');try{await api('answer_prompt',prompt.id,response);await onRefresh();}catch(e){setError(String(e));onError(e);}finally{setBusy(false);}};
 const d=prompt.data;
 return <Dialog title={prompt.kind==='credentials'?'SSH 本地登录':'确认新的主机指纹'} onClose={()=>void answer(null)}><p className="modal-intro">{d.role==='jump'?'跳板机':'目标服务器'} · {d.host_alias||d.hostname}</p><div className="fingerprint-value">{d.username?d.username+'@':''}{d.hostname}:{d.port}</div>
  {prompt.kind==='credentials'?<form onSubmit={e=>{e.preventDefault();const form=e.currentTarget;let secret=input.current?.value||'';if(!secret){setError('请输入密码或私钥口令');return;}const mode=value(form,'mode'),remember=checked(form,'remember');if(input.current)input.current.value='';void answer({secret,mode,remember});secret='';}}><p className="inline-help">密码仅用于本机 SSH 认证；不会写入 config.json 或审计日志。</p><label>认证方式<select name="mode"><option value="password">服务器密码</option><option value="passphrase">私钥口令</option></select></label><label>密码 / 私钥口令<div className="input-with-button"><input id="ssh-secret" ref={input} type={visible?'text':'password'} autoComplete="off" autoFocus required/><button type="button" className="button" onClick={()=>setVisible(!visible)} aria-label="显示或隐藏密码">{visible?'隐藏':'显示'}</button></div></label><label className="check"><input id="remember-ssh-secret" name="remember" type="checkbox" defaultChecked/>记住此凭据</label><p className="inline-help">勾选后使用 AES-256-GCM 加密保存到当前用户的数据目录；主密钥不放在项目目录。认证第 {d.attempt||1} / 3 次</p><div className="modal-actions"><button type="button" className="button" disabled={busy} onClick={()=>void answer(null)}>取消登录</button><button type="submit" className="button primary" disabled={busy}>登录</button></div></form>:<><p>通过可信渠道核对指纹，再决定是否继续连接。</p><p className="inline-help">密钥类型 {d.key_type}</p><div className="fingerprint-value">{d.fingerprint}</div><p className="inline-help">保存位置：{d.known_hosts_file}</p><div className="modal-actions"><button className="button" disabled={busy} onClick={()=>void answer(null)}>拒绝连接</button><button className="button" disabled={busy} onClick={()=>void answer('once')}>仅本次会话信任</button><button className="button primary" disabled={busy} onClick={()=>void answer('save')}>信任并保存</button></div></>}
  {error&&<div className="modal-error" role="alert">{error}</div>}
 </Dialog>;
}
