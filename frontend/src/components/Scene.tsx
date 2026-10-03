import {useEffect,useRef} from 'react';
import {redact,risk} from '../utils';
import type {Effects,RequestSummary,Server} from '../types';
// Static filler so the terrain reads as code before any real output has drifted into it. Contains no user data.
const CORPUS=['const horizon = height * (danger ? .50 : .44);','for (const row of rows) draw(row, depth, relief(row));','approve(request_id, ticket) // hold confirmed · single use','stream.read(offset, 65536).then(chunk => term.append(redact(chunk)));','ssh -o BatchMode=yes -o ConnectTimeout=8 "$TARGET" -- "$COMMAND"','policy.readonly.match(argv) ? autoAllow(request) : gate.enqueue(request);','tunnel.status === "READY" && mcp.listen(18765, "127.0.0.1");','known_hosts.verify(host, fingerprint) || prompt.confirm(fingerprint);','session.env = { ...session.env, PROJECT_MODE }; cwd = resolve(cwd);','export async function snapshot() { return api.call("snapshot"); }','if (exit_code !== 0) log.warn(`exit ${exit_code}`, stderr);','rsync -az --partial ./dist/ deploy@host:/srv/app/'];
const MONO='"Cascadia Mono","Cascadia Code",Consolas,monospace',OFFSETS=[0,.07,.02,.08,.04,.06],MIPS=[2.4,5,11,24];
const COLORS={idle:'132,144,153',connected:'236,228,214',running:'159,216,255',pending:'255,181,71',down:'255,92,122'};
// Nodes stay in the sky band (stage y ≤ .40) so they never sink into the terrain.
export function nodePosition(index:number,count:number){if(count>6)return {x:.53+(index%2)*.18,y:.12+Math.floor(index/2)*Math.min(.09,.28/Math.max(1,Math.ceil(count/2)-1))};return {x:.70+OFFSETS[index%6],y:.12+index*Math.min(.1,.28/Math.max(1,count-1))};}
export function nodeState(server:Server,requests:RequestSummary[]){return requests.some(r=>r.server_id===server.id&&r.status==='running')?'running':requests.some(r=>r.server_id===server.id&&r.status==='pending_approval')?'pending':server.connected?'idle':server.last_diagnostics?.success===false?'down':'idle';}
type Row={text:string;strip:HTMLCanvasElement|null;mip:number;ratio:number;advance:number};
// Joins whole entries into one ASCII row (long entries cut at a space); anything non-printable becomes a middle dot.
const compose=(pool:string[],q:number)=>{const parts:string[]=[];for(let j=0,n=0;n<200&&j<pool.length;j++){let s=pool[mod(q*5+j,pool.length)];if(s.length>120)s=s.slice(0,Math.max(60,s.lastIndexOf(' ',120)));parts.push(s);n+=s.length+4;}return (parts.join('    ')+'    ').replace(/[^ -~]/g,c=>c<' '?' ':'·');};
const smooth=(a:number,b:number,x:number)=>{const t=Math.min(1,Math.max(0,(x-a)/(b-a)));return t*t*(3-2*t);};
const mod=(a:number,b:number)=>((a%b)+b)%b;
const hash=(n:number)=>{const s=Math.sin(n*12.9898)*43758.5453;return s-Math.floor(s);};
// Rolling hills, 0..1: a valley straight ahead, ridges toward the sides and the horizon.
const relief=(x:number,z:number)=>{const n=Math.sin(x*.031+z*.11)*.8+Math.sin(x*.013-z*.06+1.7)+Math.sin(x*.067+z*.19+.6)*.3+Math.sin((x+z*7)*.021+4.1)*.5,r=Math.min(1,Math.max(0,n/5.2+.5));return r*r*(.3+.7*smooth(8,70,Math.abs(x)));};
export function Scene({servers,requests,focus,effects,online,terrain}:{servers:Server[];requests:RequestSummary[];focus:string|null;effects:Effects;online:boolean;terrain:React.RefObject<string[]>}){
 const canvas=useRef<HTMLCanvasElement>(null),latest=useRef({servers,requests,focus,effects,online});latest.current={servers,requests,focus,effects,online};
 const control=useRef<()=>void>(()=>{});
 useEffect(()=>{
  const el=canvas.current!,ctx=el.getContext('2d')!,layer=document.createElement('canvas'),lctx=layer.getContext('2d')!;let frame:number|null=null,last=0,previous=0,phase=0,spawn=1000,width=0,height=0,ratio=0,signature='',built=-1e9;
  let pool=CORPUS;const cache=new Map<number,Row>();
  const build=()=>{const now=performance.now(),raw=terrain.current.join('\n'),sig=raw.slice(-9000);if(sig===signature||now-built<2000)return;signature=sig;built=now;pool=[...redact(raw).split('\n').map(t=>t.trim()).filter(Boolean).slice(-24),...CORPUS];};
  // A row keeps the text it was born with, so new output only enters at the horizon.
  const row=(q:number)=>{let r=cache.get(q);if(!r){r={text:compose(pool,q),strip:null,mip:-1,ratio:0,advance:0};cache.set(q,r);if(cache.size>64)for(const key of cache.keys())if(key<spawn-50)cache.delete(key);}return r;};
  // Strips are white; tint() colours them in screen space. Each row is rasterized once per mip level and then stamped in short spans, so words stay intact while the ground bends.
  const paint=(r:Row,mip:number)=>{const font=MIPS[mip]*ratio+'px '+MONO,s=document.createElement('canvas'),g=s.getContext('2d')!;g.font=font;const advance=g.measureText('0').width;s.width=Math.ceil(advance*r.text.length)+2;s.height=Math.ceil(MIPS[mip]*ratio*1.4);g.font=font;g.fillStyle='#fff';g.textBaseline='middle';g.fillText(r.text,0,s.height/2);Object.assign(r,{strip:s,mip,ratio,advance});};
  const resize=()=>{ratio=Math.min(devicePixelRatio||1,1.5);width=innerWidth;height=innerHeight;el.width=layer.width=Math.round(width*ratio);el.height=layer.height=Math.round(height*ratio);draw(performance.now());};
  const target=()=>{const r=(document.querySelector('#prompt-history .ph.latest .caret')||document.querySelector('#prompt-history .ph.latest .ph-cmd'))?.getBoundingClientRect();return r&&r.width?{x:r.right+4,y:r.top+r.height/2}:null;};
  const land=(c:CanvasRenderingContext2D,w:number,horizon:number,bottom:number,dim:number,low:boolean)=>{
   const rows=low?26:44,near=19,far=.7,lift=(bottom-horizon)/near,cx=w*.5;
   for(let k=0;k<rows;k++){
    // Rows are spaced geometrically in depth: far rows are a fine haze, mid rows readable, near rows fade before reaching the terminal.
    const depth=(k+phase)/rows,size=far*Math.pow(near/far,depth),ground=horizon+size*lift;
    const fade=smooth(0,.14,depth)*(.3+.7*smooth(.05,.5,depth))*(1-smooth(.66,.94,depth))*dim;if(fade<.02)continue;
    const q=spawn-k,r=row(q),found=MIPS.findIndex(f=>f>=size),mip=found<0?MIPS.length-1:found;if(r.mip!==mip||r.ratio!==ratio)paint(r,mip);
    const strip=r.strip!,n=r.text.length,adv=r.advance,scale=size/(MIPS[mip]*ratio),g=adv*scale,run=Math.max(1,Math.round(22/g)),sh=strip.height,dh=sh*scale,shift=mod(q*37,n);
    for(let u=Math.floor(-cx/g/run)*run;cx+u*g<w;u+=run){
     const x=cx+u*g,h=relief(u+run/2,q),a=.5*fade*(.22+.78*h)*(.15+.85*smooth(w*.18,w*.62,x));if(a<.01)continue;
     c.globalAlpha=a;const y=ground-h*size*5-dh/2;
     for(let s0=mod(u+shift,n),left=run,dx=x;left>0;s0=0){const take=Math.min(left,n-s0);c.drawImage(strip,s0*adv,0,take*adv,sh,dx,y,take*g,dh);dx+=take*g;left-=take;}
    }
   }
   c.globalAlpha=1;
  };
  // Colours the terrain layer in place (alpha kept): teal → ice blue → violet across, a small warm pool under the nodes.
  // Keep the pool small and weak: amber over blue at higher strength mixes to grey.
  const tint=(w:number,horizon:number,t:number,danger:boolean)=>{
   lctx.globalCompositeOperation='source-atop';
   const drift=Math.sin(t*.07)*.06,across=lctx.createLinearGradient(0,0,w,0);across.addColorStop(0,'rgb(70,214,190)');across.addColorStop(.42+drift,'rgb(92,176,246)');across.addColorStop(1,'rgb(156,128,246)');
   lctx.fillStyle=across;lctx.fillRect(0,0,w,height);
   const haze=lctx.createRadialGradient(w*.72,horizon+20,0,w*.72,horizon+20,w*.2),accent=danger?'255,92,122':'255,181,71';haze.addColorStop(0,`rgba(${accent},${danger?.6:.38})`);haze.addColorStop(1,`rgba(${accent},0)`);
   lctx.fillStyle=haze;lctx.fillRect(0,0,w,height);lctx.globalCompositeOperation='source-over';
  };
  const link=(x:number,y:number,to:{x:number;y:number},rgb:string,toServer:boolean,selected:boolean,t:number,anim:boolean,i:number)=>{
   const sx=x-12,sy=y+5,cx=sx-(sx-to.x)*.12,cy=sy+(to.y-sy)*.88,g=ctx.createLinearGradient(sx,sy,to.x,to.y);
   g.addColorStop(0,`rgba(${rgb},${selected?.45:.3})`);g.addColorStop(1,`rgba(${rgb},.03)`);ctx.strokeStyle=g;ctx.lineWidth=.8;ctx.beginPath();ctx.moveTo(sx,sy);ctx.quadraticCurveTo(cx,cy,to.x,to.y);ctx.stroke();
   if(!anim)return;
   // One light travels the cable: toward the prompt for output, toward the server for a pending request.
   const p0=(t*.32+i*.29)%1,p=toServer?1-p0:p0,u=1-p,px=u*u*sx+2*u*p*cx+p*p*to.x,py=u*u*sy+2*u*p*cy+p*p*to.y,d=ctx.createRadialGradient(px,py,0,px,py,6);
   d.addColorStop(0,`rgba(${rgb},${Math.sin(p0*Math.PI)*.8})`);d.addColorStop(1,`rgba(${rgb},0)`);ctx.fillStyle=d;ctx.fillRect(px-6,py-6,12,12);
  };
  const nodes=(v:typeof latest.current,w:number,h:number,t:number,anim:boolean)=>{
   const prompt=target();
   v.servers.forEach((s,i)=>{
    const p=nodePosition(i,v.servers.length),x=30+(w-56)*p.x,y=44+h*p.y,state=nodeState(s,v.requests),selected=s.id===v.focus,live=s.connected||state!=='idle',rgb=COLORS[state==='idle'&&s.connected?'connected':state];
    if(prompt&&(selected||state==='running'||state==='pending'))link(x,y,prompt,rgb,state==='pending',selected,t,anim,i);
    let g=ctx.createRadialGradient(x,y,0,x,y,48);g.addColorStop(0,'rgba(7,8,10,.7)');g.addColorStop(1,'rgba(7,8,10,0)');ctx.fillStyle=g;ctx.fillRect(x-48,y-48,96,96);
    g=ctx.createRadialGradient(x,y,0,x,y,34);g.addColorStop(0,`rgba(${rgb},${(live?.15:.05)+(state==='pending'?.07*(1+Math.sin(t*2.6)):0)})`);g.addColorStop(1,`rgba(${rgb},0)`);ctx.fillStyle=g;ctx.fillRect(x-34,y-34,68,68);
    ctx.save();ctx.translate(x,y);ctx.rotate(-.3);ctx.lineWidth=.9;
    if(state==='pending'){const r=(t*.42)%1;ctx.strokeStyle=`rgba(${rgb},${.45*(1-r)})`;ctx.beginPath();ctx.ellipse(0,0,15+20*r,6+8*r,0,0,Math.PI*2);ctx.stroke();}
    if(state==='down')ctx.setLineDash([2,3]);
    ctx.strokeStyle=`rgba(${rgb},${live?.42:.2})`;ctx.beginPath();ctx.ellipse(0,0,15,6,0,0,Math.PI*2);ctx.stroke();ctx.setLineDash([]);
    if(selected){ctx.strokeStyle=`rgba(${rgb},.32)`;ctx.beginPath();ctx.ellipse(0,0,23,9.5,0,0,Math.PI*2);ctx.stroke();}
    const count=!live?0:state==='running'?6:state==='down'?2:4,speed=state==='running'?1.7:.55;
    for(let k=0;k<count;k++)for(let m=0;m<5;m++){const a=t*speed+k*Math.PI*2/count-m*.1;ctx.fillStyle=`rgba(${rgb},${(1-m/5)*(Math.sin(a)>0?.95:.4)})`;ctx.fillRect(Math.cos(a)*15-.8,Math.sin(a)*6-.8,1.6,1.6);}
    ctx.restore();
    const flicker=state==='down'&&anim&&Math.sin(t*11)+Math.sin(t*4.3)<-.8?.3:1;
    g=ctx.createRadialGradient(x,y,0,x,y,8);g.addColorStop(0,`rgba(${rgb},${.6*flicker})`);g.addColorStop(1,`rgba(${rgb},0)`);ctx.fillStyle=g;ctx.fillRect(x-8,y-8,16,16);
    ctx.beginPath();ctx.arc(x,y,2.3,0,Math.PI*2);if(live){ctx.fillStyle=`rgba(${rgb},${flicker})`;ctx.fill();}else{ctx.strokeStyle=`rgba(${rgb},.7)`;ctx.lineWidth=1;ctx.stroke();}
    // Leader into the DOM label, which sits 44px right of the node centre.
    ctx.strokeStyle=`rgba(${rgb},${selected?.6:.32})`;ctx.lineWidth=.8;ctx.beginPath();ctx.moveTo(x+19,y);ctx.lineTo(x+40,y);ctx.stroke();
   });
  };
  const draw=(now:number)=>{
   const v=latest.current;build();ctx.setTransform(ratio,0,0,ratio,0,0);ctx.clearRect(0,0,width,height);
   const w=width-(width<1280?46:330),h=height-74,danger=v.requests.some(r=>r.status==='pending_approval'&&risk(r)==='destructive'),anim=v.effects!=='off',low=v.effects==='low';
   const horizon=height*(danger?.5:.44),dim=(v.online?1:.5)*(danger?.6:1),t=anim?now*.001:0,tone=danger?'255,92,122':'120,186,224';
   for(let i=0,n=low?18:42;i<n;i++){const r=hash(i+7.3),x=mod(hash(i+1)*w-t*(3+r*6),w),y=48+hash(i+3.1)*(horizon-110);ctx.fillStyle=`rgba(${r>.86?'255,210,150':'170,208,240'},${(.05+.12*r)*(.6+.4*Math.sin(t*(.6+r)+i))*dim})`;ctx.fillRect(x,y,r>.8?1.5:1,r>.8?1.5:1);}
   const band=ctx.createLinearGradient(0,horizon-90,0,horizon+40);band.addColorStop(0,`rgba(${tone},0)`);band.addColorStop(.7,`rgba(${tone},${.045*dim})`);band.addColorStop(1,`rgba(${tone},0)`);ctx.fillStyle=band;ctx.fillRect(0,horizon-90,w,130);
   const line=ctx.createLinearGradient(0,0,w,0);line.addColorStop(.12,`rgba(${tone},0)`);line.addColorStop(.62,`rgba(${tone},${.2*dim})`);line.addColorStop(1,`rgba(${tone},0)`);ctx.fillStyle=line;ctx.fillRect(0,horizon,w,1);
   lctx.setTransform(ratio,0,0,ratio,0,0);lctx.clearRect(0,0,width,height);land(lctx,w,horizon,height+20,dim,low);tint(w,horizon,t,danger);
   ctx.save();ctx.setTransform(1,0,0,1,0,0);ctx.drawImage(layer,0,0);ctx.restore();nodes(v,w,h,t,anim);
  };
  const animate=(now:number)=>{frame=requestAnimationFrame(animate);const v=latest.current;if(now-last<1000/(v.effects==='low'?20:30))return;const delta=previous?Math.min(now-previous,100):0;previous=now;last=now;
   if(v.online&&v.effects!=='off'){phase+=delta*.0005*(v.effects==='low'?.5:1)*(v.requests.some(r=>r.status==='pending_approval'&&risk(r)==='destructive')?.38:1);while(phase>=1){phase-=1;spawn++;}}draw(now);};
  const sync=()=>{if(document.hidden||latest.current.effects==='off'){if(frame!==null)cancelAnimationFrame(frame);frame=null;previous=0;if(!document.hidden)draw(0);}else if(frame===null)frame=requestAnimationFrame(animate);};
  control.current=sync;
  resize();sync();window.addEventListener('resize',resize);document.addEventListener('visibilitychange',sync);
  return()=>{if(frame!==null)cancelAnimationFrame(frame);window.removeEventListener('resize',resize);document.removeEventListener('visibilitychange',sync);};
 },[terrain]);
 useEffect(()=>control.current(),[effects,online,servers,requests,focus]);
 return <canvas id="scene" ref={canvas} aria-hidden="true"/>;
}
