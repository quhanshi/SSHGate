import {orbitElapsed} from './connection';
import type {OrbitState} from './connection';
import {fingerprintArt} from './fingerprint';
import {hopSpan,orbitCurve} from './orbitPath';
import type {Box,Point} from './orbitPath';

type Motion={seq:number;outcome:string;from:number;to:number;since:number;key:string};
export interface OrbitPaintOptions {animate:boolean;live:boolean;panel?:Box}
const MONO='"Cascadia Mono","Cascadia Code",Consolas,monospace',SUCCESS='155,221,203';
// This cache only interpolates toward an observed event; time never selects a stage.
export function createOrbitPainter(){
 const motions=new Map<string,Motion>(),arts=new Map<string,ReturnType<typeof fingerprintArt>>(),seals=new Map<string,{open:boolean;at:number}>();
 const artOf=(value:string)=>{let art=arts.get(value);if(art===undefined){if(arts.size>8)arts.clear();art=fingerprintArt(value);arts.set(value,art);}return art;};
 return (ctx:CanvasRenderingContext2D,o:OrbitState,start:Point,end:Point,now:number,{animate,live,panel}:OrbitPaintOptions)=>{
  const key=`${o.request.request_id}:${o.context.hop_index}:${o.attempt}`,id=o.request.server_id;
  let m=motions.get(id);
  const progress=(v:Motion)=>v.from+(v.to-v.from)*(1-Math.pow(1-Math.min(1,Math.max(0,(now-v.since)/380)),3));
  if(!m||m.key!==key){m={seq:o.last.seq,outcome:o.outcome,from:o.cable,to:o.cable,since:now,key};motions.set(id,m);}
  else if(m.seq!==o.last.seq||m.outcome!==o.outcome){m={...m,seq:o.last.seq,outcome:o.outcome,from:progress(m),to:o.cable,since:now};motions.set(id,m);}
  // Terminal outcomes snap to the last observed stage; no success is played after a failure.
  const failed=o.outcome==='failed'||o.outcome==='cancelled',success=o.outcome==='connected'||o.outcome==='reused',jump=o.context.role==='jump';
  const age=animate?Math.max(0,now-m.since):2000;
  let hop=animate&&!failed?progress(m):m.to;
  // A short recoil marks a real rejection: TCP refused, or the server turning down an authentication method.
  const recoil=failed?(o.code==='connection_refused'?.09:o.code==='authentication_failed'?.05:0):o.last.event==='authentication_method_failed'?.05:0;
  if(animate&&recoil)hop-=Math.sin(Math.min(1,age/420)*Math.PI)*recoil;
  hop=Math.min(1,Math.max(0,hop));
  const rgb=failed?'255,102,126':o.stage==='host_key'&&!o.trusted?'245,192,112':success?SUCCESS:'146,205,235';
  const alpha=failed&&o.code==='timeout'?Math.max(.25,1-age/1600):1;
  // The status panel covers the start of the path; map observed progress onto the visible part only.
  const {point,visible:t0}=orbitCurve(start,end,panel);
  const span=hopSpan(t0,o.context.hop_index,o.context.hop_count),{at,n:hops,h}=span,from=span.from,p=span.from+(span.to-span.from)*hop;
  const stroke=(a:number,b:number,color:string,dashed:boolean)=>{
   const steps=Math.max(2,Math.ceil((b-a)*96));ctx.beginPath();
   for(let i=0;i<=steps;i++){const q=point(a+(b-a)*i/steps);if(i)ctx.lineTo(q.x,q.y);else ctx.moveTo(q.x,q.y);}
   ctx.setLineDash(dashed?[4,5]:[]);ctx.strokeStyle=`rgba(${color},.46)`;ctx.lineWidth=1;ctx.stroke();ctx.setLineDash([]);
   ctx.strokeStyle=`rgba(${color},.07)`;ctx.lineWidth=5;ctx.stroke();
  };
  // One sweep when this view saw the transport switch to encrypted; never replayed for a trace loaded already sealed.
  const seal=seals.get(key);
  if(!o.encrypted)seals.set(key,{open:true,at:0});else if(seal?.open)seals.set(key,{open:false,at:now});
  if(seals.size>16)for(const k of seals.keys())if(k!==key)seals.delete(k);
  const swept=(now-(seals.get(key)?.at||-1e9))/650;
  ctx.save();
  if(animate&&swept>=0&&swept<1){
   const scale=ctx.getTransform().a||1,w=ctx.canvas.width/scale,y=44+(ctx.canvas.height/scale-74)*(1-Math.pow(1-swept,2)),g=ctx.createLinearGradient(0,0,w,0);
   g.addColorStop(0,'rgba(146,205,235,0)');g.addColorStop(.5,`rgba(146,205,235,${.32*(1-swept)})`);g.addColorStop(1,'rgba(146,205,235,0)');ctx.fillStyle=g;ctx.fillRect(0,y,w,1);
  }
  ctx.globalAlpha=alpha;ctx.font=`10px ${MONO}`;
  // Earlier hops are authenticated connections. The current hop stays dashed until its transport is encrypted.
  // Nothing is drawn under the panel: its translucent background would show the cable through the text.
  if(h>1)stroke(t0,from,SUCCESS,false);
  if(p>from)stroke(from,p,rgb,!o.encrypted);
  for(let k=1;k<hops&&k<=h;k++){
   if(k===h&&!jump)continue;
   const q=point(at(k)),reached=k<h||o.waitingForTarget,color=reached?SUCCESS:rgb,label=o.jumps[k-1];
   ctx.strokeStyle=`rgba(${color},${reached?.7:.45})`;ctx.lineWidth=1;ctx.strokeRect(q.x-4.5,q.y-4.5,9,9);
   if(reached){ctx.fillStyle=`rgba(${color},.6)`;ctx.fillRect(q.x-1.5,q.y-1.5,3,3);}
   // The path runs up and to the right, so the lower right of a waypoint stays clear of it.
   if(label){ctx.fillStyle=`rgba(${color},.75)`;ctx.textAlign='left';ctx.textBaseline='top';ctx.fillText(label,q.x+9,q.y+4);}
  }
  const tip=point(p),breathe=animate&&!success&&!failed?.65+.35*Math.sin(now*.003):1;
  const glow=ctx.createRadialGradient(tip.x,tip.y,0,tip.x,tip.y,12);
  glow.addColorStop(0,`rgba(${rgb},${.5*breathe})`);glow.addColorStop(1,`rgba(${rgb},0)`);ctx.fillStyle=glow;ctx.fillRect(tip.x-12,tip.y-12,24,24);
  ctx.fillStyle=`rgba(${rgb},.95)`;ctx.beginPath();ctx.arc(tip.x,tip.y,failed?1.8:2.4,0,Math.PI*2);ctx.fill();
  // The tip carries the route clock while live, and the final time where a failure stopped it.
  if((live&&o.outcome==='active')||failed){
   const ms=failed?o.last.elapsed_ms:orbitElapsed(o,Date.now(),true);
   ctx.fillStyle=`rgba(${failed?rgb:'159,216,255'},.8)`;ctx.textAlign='left';ctx.textBaseline='top';ctx.fillText((ms/1000).toFixed(2)+'s',tip.x+8,tip.y+7);
  }
  // A jump host is a waypoint; never attach its identity or success light to the target.
  if(jump){ctx.restore();return;}
  const brackets=(rx:number,ry:number,color:string,opacity:number,dashed=false)=>{
   ctx.strokeStyle=`rgba(${color},${opacity})`;ctx.lineWidth=.8;ctx.setLineDash(dashed?[2,2]:[]);
   for(const dx of [-1,1])for(const dy of [-1,1]){ctx.beginPath();ctx.moveTo(end.x+dx*(rx-5),end.y+dy*ry);ctx.lineTo(end.x+dx*rx,end.y+dy*ry);ctx.lineTo(end.x+dx*rx,end.y+dy*(ry-5));ctx.stroke();}
   ctx.setLineDash([]);
  };
  // No shared algorithm: the frame closes on an empty centre.
  if(failed&&o.code==='algorithm_mismatch'){brackets(24,24,rgb,.55,true);ctx.restore();return;}
  const art=artOf(String(o.metadata.fingerprint||''));
  if(art){
   // 17 x 9 cells span ±8 x ±4 spacings; the frame closes 4px outside them, and sits looser until the key is trusted.
   const spacing=3.2,ox=end.x-8*spacing,oy=end.y-4*spacing,pad=o.trusted?4:9;
   // A changed key: the recorded constellation is drawn hollow and offset beside the received one.
   const saved=o.hostKey==='mismatch'?artOf(String(o.metadata.expected_fingerprint||'')):null;
   if(saved){ctx.strokeStyle=`rgba(${rgb},.45)`;ctx.lineWidth=.6;saved.visits.forEach((row,y)=>row.forEach((n,x)=>{if(!n)return;ctx.beginPath();ctx.arc(ox+x*spacing+2,oy+y*spacing+1.5,.8+Math.sqrt(n)*.2,0,Math.PI*2);ctx.stroke();}));}
   art.visits.forEach((row,y)=>row.forEach((n,x)=>{if(!n)return;ctx.fillStyle=`rgba(${rgb},${.16+Math.min(1,n/10)*.55})`;ctx.beginPath();ctx.arc(ox+x*spacing,oy+y*spacing,.45+Math.sqrt(n)*.2,0,Math.PI*2);ctx.fill();}));
   brackets(8*spacing+pad,4*spacing+pad,rgb,o.trusted?.65:.4);
  }
  ctx.restore();
 };
}
