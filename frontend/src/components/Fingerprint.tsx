import {useMemo} from 'react';
import {fingerprintArt} from '../fingerprint';
export function Fingerprint({value,trusted=false}:{value:string;trusted?:boolean}){
 const art=useMemo(()=>fingerprintArt(value),[value]);
 if(!art)return null;
 return <figure className={'fingerprint-art '+(trusted?'verified':'unverified')}>
  <svg viewBox="0 0 180 100" role="img" aria-label="主机 SHA256 指纹图，17 列 9 行" data-fingerprint={value}>
   <path className="fingerprint-corners" d="M1 13V1H13 M167 1H179V13 M179 87V99H167 M13 99H1V87"/>
   {art.visits.flatMap((row,y)=>row.map((n,x)=>{const marker=(x===8&&y===4)||(x===art.end.x&&y===art.end.y);return <circle key={y*17+x} cx={10+x*10} cy={10+y*10} r={marker?2.1:n?1+Math.sqrt(n)*.48:.45} opacity={marker?.95:n?.3+Math.min(n/14,1)*.7:.12}/>;}))}
  </svg>
  <figcaption>{trusted?'指纹已核验':'待核验的指纹'}<span>SHA256 · 17 × 9</span></figcaption>
 </figure>;
}
