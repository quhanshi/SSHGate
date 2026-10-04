import type {OrbitState} from './connection';
import {fingerprintArt} from './fingerprint';

type Point={x:number;y:number};
type Motion={seq:number;outcome:string;from:number;to:number;since:number;key:string};
// This cache only interpolates toward an observed event; time never selects a stage.
export function createOrbitPainter(){
 const motions=new Map<string,Motion>();
 let fingerprint='',art:ReturnType<typeof fingerprintArt>=null;
 return (ctx:CanvasRenderingContext2D,o:OrbitState,start:Point,end:Point,now:number,animate:boolean)=>{
  const key=`${o.request.request_id}:${o.context.hop_index}:${o.attempt}`,id=o.request.server_id;
  let m=motions.get(id);
  const progress=(v:Motion)=>v.from+(v.to-v.from)*(1-Math.pow(1-Math.min(1,Math.max(0,(now-v.since)/380)),3));
  if(!m||m.key!==key){m={seq:o.last.seq,outcome:o.outcome,from:o.cable,to:o.cable,since:now,key};motions.set(id,m);}
  else if(m.seq!==o.last.seq||m.outcome!==o.outcome){m={...m,seq:o.last.seq,outcome:o.outcome,from:progress(m),to:o.cable,since:now};motions.set(id,m);}
  // Terminal outcomes snap to the last observed stage; no success is played after a failure.
  const failed=o.outcome==='failed'||o.outcome==='cancelled',success=o.outcome==='connected'||o.outcome==='reused';
  const age=animate?Math.max(0,now-m.since):2000;
  let p=(animate&&!failed?progress(m):m.to)*(o.context.role==='jump'?.55:1);
  if(animate&&failed&&o.code==='connection_refused')p-=Math.sin(Math.min(1,age/420)*Math.PI)*.09;
  p=Math.max(0,p);
  const rgb=failed?'255,102,126':o.stage==='host_key'&&!o.trusted?'245,192,112':success?'155,221,203':'146,205,235';
  const alpha=failed&&o.code==='timeout'?Math.max(.25,1-age/1600):1;
  const c1={x:start.x+(end.x-start.x)*.73,y:start.y-18},c2={x:end.x-20,y:end.y+(start.y-end.y)*.54};
  const point=(v:number)=>{const u=1-v;return {x:u*u*u*start.x+3*u*u*v*c1.x+3*u*v*v*c2.x+v*v*v*end.x,y:u*u*u*start.y+3*u*u*v*c1.y+3*u*v*v*c2.y+v*v*v*end.y};};
  ctx.save();ctx.globalAlpha=alpha;
  if(failed&&o.code==='algorithm_mismatch')ctx.setLineDash([5,7]);
  ctx.beginPath();ctx.moveTo(start.x,start.y);
  for(let i=1;i<=72;i++){const q=point(Math.max(0,p)*i/72);ctx.lineTo(q.x,q.y);}
  ctx.strokeStyle=`rgba(${rgb},.46)`;ctx.lineWidth=1;ctx.stroke();ctx.setLineDash([]);
  ctx.strokeStyle=`rgba(${rgb},.07)`;ctx.lineWidth=5;ctx.stroke();
  const tip=point(p),breathe=animate&&!success&&!failed?.65+.35*Math.sin(now*.003):1;
  const glow=ctx.createRadialGradient(tip.x,tip.y,0,tip.x,tip.y,12);
  glow.addColorStop(0,`rgba(${rgb},${.5*breathe})`);glow.addColorStop(1,`rgba(${rgb},0)`);ctx.fillStyle=glow;ctx.fillRect(tip.x-12,tip.y-12,24,24);
  ctx.fillStyle=`rgba(${rgb},.95)`;ctx.beginPath();ctx.arc(tip.x,tip.y,failed?1.8:2.4,0,Math.PI*2);ctx.fill();
  // A jump host is a waypoint; never attach its identity or success light to the target.
  if(o.context.role==='jump'){ctx.strokeStyle=`rgba(${rgb},.6)`;ctx.strokeRect(tip.x-5,tip.y-5,10,10);ctx.restore();return;}
  const value=String(o.metadata.fingerprint||'');if(value!==fingerprint){fingerprint=value;art=fingerprintArt(value);}
  if(art){
   const spacing=4.4,ox=end.x-8*spacing,oy=end.y-4*spacing;
   art.visits.forEach((row,y)=>row.forEach((n,x)=>{if(!n)return;ctx.fillStyle=`rgba(${rgb},${.16+Math.min(1,n/10)*.55})`;ctx.beginPath();ctx.arc(ox+x*spacing,oy+y*spacing,.5+Math.sqrt(n)*.22,0,Math.PI*2);ctx.fill();}));
   const r=o.trusted?19:28;ctx.strokeStyle=`rgba(${rgb},${o.trusted?.65:.4})`;ctx.lineWidth=.8;
   for(const dx of [-1,1])for(const dy of [-1,1]){ctx.beginPath();ctx.moveTo(end.x+dx*(r-5),end.y+dy*r);ctx.lineTo(end.x+dx*r,end.y+dy*r);ctx.lineTo(end.x+dx*r,end.y+dy*(r-5));ctx.stroke();}
  }
  ctx.restore();
 };
}
