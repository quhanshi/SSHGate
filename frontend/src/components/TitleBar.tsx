import {useCallback,useEffect,useState} from 'react';
import {api} from '../api';
import type {WindowState} from '../types';
// Same shapes as assets/app.svg: the gate arch over a shell prompt.
export function AppMark(){
 return <svg className="app-mark" viewBox="0 0 256 256" aria-hidden="true"><path d="M70 198V120a58 58 0 0 1 116 0v78" fill="none" stroke="#7fdcef" strokeWidth="20" strokeLinecap="round"/><path d="M104 132l24 22-24 22" fill="none" stroke="#eef0ea" strokeWidth="18" strokeLinecap="round" strokeLinejoin="round"/><path d="M138 178h24" stroke="#ffb547" strokeWidth="18" strokeLinecap="round"/></svg>;
}
// Native caption state. Outside the desktop app (or if the frame could not be replaced) the system title bar stays.
export function useWindowFrame(){
 const [state,setState]=useState<WindowState>({custom_frame:false,maximized:false});
 useEffect(()=>{
  let live=true;const read=()=>{if(window.pywebview?.api?.window_state)api('window_state').then(s=>{if(live)setState(s);},()=>{});};
  read();window.addEventListener('pywebviewready',read);window.addEventListener('resize',read);
  return()=>{live=false;window.removeEventListener('pywebviewready',read);window.removeEventListener('resize',read);};
 },[]);
 const act=useCallback((action:'minimize'|'maximize'|'close')=>{api('window_action',action).then(setState,()=>{});},[]);
 return {frame:state,windowAction:act};
}
export function WindowControls({maximized,onAction}:{maximized:boolean;onAction:(action:'minimize'|'maximize'|'close')=>void}){
 return <div className="window-controls" role="group" aria-label="窗口">
  <button id="window-minimize" onClick={()=>onAction('minimize')} aria-label="最小化" title="最小化"><svg viewBox="0 0 10 10"><path d="M0 5.5h10"/></svg></button>
  <button id="window-maximize" onClick={()=>onAction('maximize')} aria-label={maximized?'还原':'最大化'} title={maximized?'还原':'最大化'}>{maximized?<svg viewBox="0 0 10 10"><path d="M2.5 2.5V.5h7v7h-2M.5 2.5h7v7h-7z"/></svg>:<svg viewBox="0 0 10 10"><path d="M.5.5h9v9h-9z"/></svg>}</button>
  <button id="window-close" className="close" onClick={()=>onAction('close')} aria-label="关闭" title="关闭"><svg viewBox="0 0 10 10"><path d="M.5.5l9 9M9.5.5l-9 9"/></svg></button>
 </div>;
}
