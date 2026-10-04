import type {Snapshot,RequestDetail,RequestSummary,Profiles,Route,Transfer,Session} from './types';
interface ApiMap {
 snapshot: [[],Snapshot]; request_detail:[[string,number?],RequestDetail]; begin_review:[[string],{ticket:string;request:RequestDetail}]; approve:[[string,string,boolean],null]; reject:[[string],unknown]; terminate_request:[[string],RequestDetail];
 set_readonly:[[boolean],unknown]; save_settings:[[Record<string,unknown>],unknown]; set_mcp_running:[[boolean],unknown];
 revoke_authorization:[[string],unknown];
 known_hosts:[[],{host:string;port:number}[]]; ssh_profiles:[[string?],Profiles]; preview_connection:[[Record<string,unknown>],Route]; save_connection:[[Record<string,unknown>,boolean],{id:string}]; remove_connection:[[string],unknown]; test_connection:[[string],RequestSummary]; disconnect_connection:[[string?],unknown];
 filesystem:[[string,string,Record<string,unknown>],RequestSummary]; prepare_upload:[[],Transfer|null]; save_download:[[string],string|null]; clear_transfer:[[string],unknown]; choose_file:[[string],string];
 session_action:[[string,Record<string,unknown>],RequestSummary]; session_detail:[[string],Session]; submit_local:[[string,string,string,string,number],RequestSummary];
 save_tunnel:[[Record<string,unknown>],unknown]; start_tunnel:[[string,boolean],unknown]; clear_tunnel_api_key:[[],unknown]; stop_tunnel:[[],unknown]; download_tunnel:[[],unknown]; proxy_action:[[string,string?,string?],unknown]; open_external:[[string],unknown];
 answer_prompt:[[string,unknown],unknown]; export_output:[[string],string|null];
}
declare global {interface Window {__APP_TOKEN__?:string;pywebview?:{api:Record<string,(token:string,...args:unknown[])=>Promise<{ok:boolean;data?:unknown;error?:string}>>};SSHUI?:{refresh:()=>Promise<void>;go:(page:string)=>void;diagnostics:()=>Record<string,unknown>}}}
export async function api<K extends keyof ApiMap>(method:K,...args:ApiMap[K][0]):Promise<ApiMap[K][1]> {
 const bridge=window.pywebview?.api;
 if(!bridge?.[method]) throw new Error('请使用 Start-App.cmd 从桌面应用启动。');
 const reply=await bridge[method](window.__APP_TOKEN__||'',...args);
 if(!reply?.ok) throw new Error(reply?.error||'本地操作未完成');
 return reply.data as ApiMap[K][1];
}
export async function copy(text:string){
 try {await navigator.clipboard.writeText(text);} catch {
  const input=document.createElement('textarea');input.value=text;input.style.cssText='position:fixed;left:-10000px';document.body.append(input);input.select();const ok=document.execCommand('copy');input.remove();if(!ok)throw new Error('复制未完成，请手动选择文本复制。');
 }
}
