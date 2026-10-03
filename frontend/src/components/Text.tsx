import {useMemo} from 'react';
import {dangerPattern,redact,statusLabels} from '../utils';
export function DisplayText({text,danger=false}:{text:string;danger?:boolean}){
 const value=useMemo(()=>redact(text),[text]);
 const matches=useMemo(()=>{
  const regex=danger?new RegExp(dangerPattern.source,'gi'):/\b\d+(?:\.\d+)?(?:\s?(?:ms|s|bytes|MiB|KiB|MB|GB|%))?\b/g;
  return [...value.matchAll(regex)];
 },[value,danger]);
 let pos=0;const children:React.ReactNode[]=[];
 for(const m of matches){if(m.index!>pos)children.push(value.slice(pos,m.index));children.push(<span className={danger?'danger':'num'} key={m.index}>{m[0]}</span>);pos=m.index!+m[0].length;}
 children.push(value.slice(pos));return <>{children}</>;
}
export function Badge({status}:{status:string}){return <span className={'badge '+(status==='succeeded'?'green':status==='pending_approval'?'amber':status==='running'?'blue':['failed','timed_out','terminated','termination_unconfirmed'].includes(status)?'red':'')}>{statusLabels[status]||status}</span>;}
export function Empty({children}:{children:React.ReactNode}){return <div className="empty-state">{children}</div>;}
