import type {RequestDetail,RequestSummary,Line} from './types.ts';
export const statusLabels:Record<string,string>={pending_approval:'等待审批',queued_readonly:'只读排队',running:'执行中',succeeded:'成功',failed:'失败',denied:'已拒绝',expired:'已过期',timed_out:'已超时',disconnected:'已断开',terminated:'已终止',termination_unconfirmed:'终止未确认'};
export const phaseLabels:Record<string,string>={waiting_approval:'等待审批',connecting:'准备连接',resolving_dns:'解析 DNS',connecting_tcp:'连接 TCP',opening_jump_channel:'建立跳板转发',starting_proxy:'启动本地代理',handshaking_ssh:'SSH 握手',authenticating:'SSH 认证',awaiting_local_credentials:'等待本地密码',connected:'已连接',opening_sftp:'打开文件通道',checking_cwd:'检查目录',checking_default_cwd:'检查默认目录',executing:'远程执行',terminating:'正在终止',finished:'已结束'};
export const active=(r:RequestSummary)=>['running','pending_approval','queued_readonly'].includes(r.status);
export const stamp=(value:string|number|null|undefined)=>value?new Date(value).toLocaleTimeString('zh-CN',{hour12:false}):'—';
export const elapsed=(n:number)=>[Math.floor(n/3600),Math.floor(n/60)%60,Math.floor(n)%60].map(x=>String(x).padStart(2,'0')).join(':');
export const clean=(s:string)=>s.replace(/\x1b\[[0-?]*[ -/]*[@-~]/g,'').replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g,'');
// Only the display is redacted. Offsets preserve the exact source text for selection copy.
export function redactWithMap(raw:string):{text:string;map:number[]} {
 const patterns=[/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)/g,/(?:\b(?:password|token|secret|api[_-]?key)\b["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;]+)/gi,/\bAuthorization\s*:\s*Bearer\s+[^\s]+/gi,/\b(?:sk-[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{12,}|AKIA[A-Z0-9]{16})\b/g,/\b[a-fA-F0-9]{32,}\b/g,/(?<![\w/])[a-zA-Z0-9+/]{64,}={0,2}(?![\w/])/g];
 const ranges:{start:number;end:number}[]=[];
 for(let i=0;i<patterns.length;i++)for(const m of raw.matchAll(patterns[i])){
  let start=m.index!;const end=start+m[0].length;
  if(i===1){const p=m[0].match(/^[\s\S]*?[:=]\s*/)!;start+=p[0].length;}
  if(i===2)start+=m[0].match(/^.*?Bearer\s+/i)![0].length;
  ranges.push({start,end});
 }
 ranges.sort((a,b)=>a.start-b.start||b.end-a.end);
 const merged:{start:number;end:number}[]=[];for(const r of ranges){const p=merged.at(-1);if(p&&r.start<=p.end)p.end=Math.max(p.end,r.end);else merged.push({...r});}
 let text='',cursor=0;const map=[0];
 for(const r of merged){for(;cursor<r.start;cursor++){text+=raw[cursor];map.push(cursor+1);}text+='••••';for(let j=1;j<=4;j++)map.push(j===4?r.end:r.start);cursor=r.end;}
 for(;cursor<raw.length;cursor++){text+=raw[cursor];map.push(cursor+1);}return {text,map};
}
export const redact=(s:string)=>redactWithMap(s).text;
export const dangerPattern=/\b(?:rm\s+(?:-[\w]*r[\w]*f[\w]*|-[\w]*f[\w]*r[\w]*)|git\s+(?:reset\s+--hard|clean\b[^\n]*-[\w]*f|push\b[^\n]*--force)|mkfs(?:\.\w+)?|wipefs|shutdown|reboot|dd\s+[^\n]*\bof=|DROP\s+(?:TABLE|DATABASE)|TRUNCATE\s+TABLE|chmod\s+(?:-[Rr]\s+)?777)\b/gi;
export function risk(d:Partial<RequestDetail>|RequestSummary):'readonly'|'write'|'destructive' {
 const text=('command' in d?d.command:('command_preview' in d?d.command_preview:''))||'';dangerPattern.lastIndex=0;
 if(dangerPattern.test(text)||('operation' in d&&d.operation==='upload_file'&&'command' in d&&/overwrite.*true/i.test(text)))return 'destructive';
 return ('readonly_eligible' in d&&d.readonly_eligible)||d.approval_kind==='auto_readonly'?'readonly':'write';
}
export function appendLines(previous:Line[],incoming:Omit<Line,'id'|'count'>[],nextId:()=>number):{lines:Line[];retired:Line[]} {
 const lines=[...previous];for(const n of incoming){const last=lines.at(-1);if(last&&last.server===n.server&&last.request===n.request&&last.kind===n.kind&&last.raw===n.raw&&n.kind!=='cmd'){lines[lines.length-1]={...last,count:last.count+1};}else lines.push({...n,id:nextId(),count:1});}
 return {lines:lines.slice(-500),retired:lines.slice(0,Math.max(0,lines.length-500))};
}
