/* Rebuilds assets/app.ico from assets/app.svg: node scripts/build_icon.cjs (needs frontend/node_modules and Chrome via SSH_UI_CHROME). */
const fs=require('fs'),path=require('path');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'../frontend/node_modules/playwright');
const root=path.resolve(__dirname,'..'),svg=fs.readFileSync(path.join(root,'assets/app.svg')),sizes=[16,20,24,32,40,48,64,128,256];
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:process.env.SSH_UI_CHROME||undefined}),page=await browser.newPage();
 const images=[];
 for(const size of sizes){
  await page.setViewportSize({width:size,height:size});
  await page.setContent(`<style>html,body{margin:0;background:transparent}img{display:block}</style><img src="data:image/svg+xml;base64,${svg.toString('base64')}" width="${size}" height="${size}">`);
  await page.waitForFunction(()=>document.images[0].complete);
  images.push(await page.screenshot({omitBackground:true,clip:{x:0,y:0,width:size,height:size}}));
 }
 await browser.close();
 // ICO with PNG-compressed entries (Windows Vista+).
 const head=Buffer.alloc(6+16*images.length);head.writeUInt16LE(0,0);head.writeUInt16LE(1,2);head.writeUInt16LE(images.length,4);
 let offset=head.length;images.forEach((png,i)=>{const e=6+16*i,s=sizes[i]%256;head.writeUInt8(s,e);head.writeUInt8(s,e+1);head.writeUInt16LE(1,e+4);head.writeUInt16LE(32,e+6);head.writeUInt32LE(png.length,e+8);head.writeUInt32LE(offset,e+12);offset+=png.length;});
 fs.writeFileSync(path.join(root,'assets/app.ico'),Buffer.concat([head,...images]));console.log('assets/app.ico: '+sizes.join(', '));
})().catch(e=>{console.error(e);process.exitCode=1;});
