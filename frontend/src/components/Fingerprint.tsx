import {useMemo} from 'react';
import {fingerprintArt} from '../fingerprint';
import type {HostKeyState} from '../connection';
const captions:Record<HostKeyState,string>={verified:'指纹已核验',pending:'待核验的指纹',incomplete:'未完成核验',mismatch:'与已保存指纹不符',rejected:'已拒绝此指纹'};
export function Fingerprint({value,state='pending',expected=''}:{value:string;state?:HostKeyState;expected?:string}){
 const art=useMemo(()=>fingerprintArt(value),[value]);
 // On a mismatch the saved key is drawn as hollow rings, offset, so the two maps visibly disagree.
 const saved=useMemo(()=>state==='mismatch'&&expected!==value?fingerprintArt(expected):null,[state,expected,value]);
 if(!art)return null;
 return <figure className={`fingerprint-art ${state==='verified'?'verified':'unverified'} ${state}`}>
  <svg viewBox="0 0 180 100" role="img" aria-label={saved?'主机 SHA256 指纹图：实心为本次收到的指纹，空心为已保存的指纹':'主机 SHA256 指纹图，17 列 9 行'} data-fingerprint={value}>
   <path className="fingerprint-corners" d="M1 13V1H13 M167 1H179V13 M179 87V99H167 M13 99H1V87"/>
   {saved&&<g className="fingerprint-saved" transform="translate(3 2.5)">{saved.visits.flatMap((row,y)=>row.map((n,x)=>n?<circle key={y*17+x} cx={10+x*10} cy={10+y*10} r={1.4+Math.sqrt(n)*.5}/>:null))}</g>}
   {art.visits.flatMap((row,y)=>row.map((n,x)=>{const marker=(x===8&&y===4)||(x===art.end.x&&y===art.end.y);return <circle key={y*17+x} cx={10+x*10} cy={10+y*10} r={marker?2.1:n?1+Math.sqrt(n)*.48:.45} opacity={marker?.95:n?.3+Math.min(n/14,1)*.7:.12}/>;}))}
  </svg>
  <figcaption>{captions[state]}<span>{saved?'实心 本次 · 空心 已保存':'SHA256 · 17 × 9'}</span></figcaption>
 </figure>;
}
