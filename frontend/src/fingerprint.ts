export interface FingerprintArt {rows:string[]; visits:number[][]; end:{x:number;y:number}}
// OpenSSH's 17 x 9 drunken-bishop walk, using the SHA256 digest (not the public key).
// Two bits per move, least significant pair first; edges clamp, they do not wrap.
export function fingerprintArt(fingerprint:string):FingerprintArt|null {
 if(!/^SHA256:[A-Za-z0-9+/]{43}=?$/.test(fingerprint))return null;
 let digest:string;
 try{digest=atob(fingerprint.slice(7));}catch{return null;}
 if(digest.length!==32)return null;
 const visits=Array.from({length:9},()=>Array<number>(17).fill(0));let x=8,y=4;
 for(const char of digest){let byte=char.charCodeAt(0);for(let i=0;i<4;i++){
  x=Math.max(0,Math.min(16,x+((byte&1)?1:-1)));y=Math.max(0,Math.min(8,y+((byte&2)?1:-1)));
  visits[y][x]=Math.min(14,visits[y][x]+1);byte>>=2;
 }}
 const symbols=' .o+=*BOX@%&#/^',rows=visits.map(row=>row.map(n=>symbols[n]));
 rows[4][8]='S';rows[y][x]='E';
 return {rows:rows.map(row=>row.join('')),visits,end:{x,y}};
}
