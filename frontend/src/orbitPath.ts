export type Point={x:number;y:number};
export type Box={left:number;top:number;right:number;bottom:number};
const inside=(q:Point,b:Box)=>q.x>=b.left&&q.x<=b.right&&q.y>=b.top&&q.y<=b.bottom;
// The cable path, plus the parameter where it leaves the status panel that covers its start.
export function orbitCurve(start:Point,end:Point,panel?:Box){
 const c1={x:start.x+(end.x-start.x)*.73,y:start.y-18},c2={x:end.x-20,y:end.y+(start.y-end.y)*.54};
 const point=(v:number)=>{const u=1-v;return {x:u*u*u*start.x+3*u*u*v*c1.x+3*u*v*v*c2.x+v*v*v*end.x,y:u*u*u*start.y+3*u*u*v*c1.y+3*u*v*v*c2.y+v*v*v*end.y};};
 let visible=0;
 if(panel&&!inside(end,panel))for(let i=96;i>=0;i--)if(inside(point(i/96),panel)){visible=(i+1)/96;break;}
 return {point,visible};
}
// Each hop owns an equal share of the visible path; jump hosts sit at the boundaries.
export function hopSpan(visible:number,index:number,count:number){
 const n=Math.max(1,count||1),h=Math.min(n,Math.max(1,index||1)),at=(k:number)=>visible+(1-visible)*k/n;
 return {from:at(h-1),to:at(h),at,n,h};
}
