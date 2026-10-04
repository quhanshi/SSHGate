/* Production assets, local approval bridge, and bounded grant lifecycle. No live SSH. */
const fs=require('fs'),path=require('path'),os=require('os'),assert=require('assert'),{spawn}=require('child_process'),readline=require('readline');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'../frontend/node_modules/playwright');
const root=path.resolve(__dirname,'..'),output=process.env.SSH_UI_OUTPUT||path.join(root,'preview'),html=path.join(os.tmpdir(),'ssh-grants-'+require('crypto').randomUUID()+'.html');fs.mkdirSync(output,{recursive:true});
const python=process.env.SSH_UI_PYTHON||path.join(root,'.venv',process.platform==='win32'?'Scripts':'bin',process.platform==='win32'?'python.exe':'python');
const child=spawn(python,['tests/fixture_desktop.py',html,'empty'],{cwd:root,stdio:['pipe','pipe','pipe']});
let readyResolve,readyReject,next=1,stderr='',browser,page;const checks=[],errors=[],pending=new Map();
const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
child.stderr.on('data',c=>stderr+=c.toString());readline.createInterface({input:child.stdout}).on('line',line=>{try{const x=JSON.parse(line);if(x.ready)readyResolve(x);else{pending.get(x.id)?.resolve(x.result);pending.delete(x.id);}}catch(e){readyReject(e);}});
child.on('error',readyReject);child.on('exit',code=>{if(code){const e=new Error(stderr||'Fixture exited '+code);readyReject(e);for(const p of pending.values())p.reject(e);}});
const rpc=(method,args=[])=>new Promise((resolve,reject)=>{const id=next++;pending.set(id,{resolve,reject});child.stdin.write(JSON.stringify({id,method,args})+'\n');});
const methods=['snapshot','request_detail','begin_review','approve','reject','set_readonly','submit_local','save_settings','revoke_authorization'];
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const refresh=async()=>{await page.evaluate(()=>window.SSHUI.refresh());await sleep(80);};
const check=async(name,fn)=>{await fn();checks.push(name);console.log('PASS '+name);};
const button=id=>page.locator(`[data-request-id="${id}"] .hold`);
const readyButton=async id=>{await button(id).waitFor();await page.waitForFunction(id=>!document.querySelector(`[data-request-id="${id}"] .hold`).disabled,id);};
const waitStatus=async(id,status)=>{await page.waitForFunction(async([id,status])=>{const x=await window.desktopRPC('snapshot',[]);return x.data.requests.find(r=>r.request_id===id)?.status===status;},[id,status]);await refresh();};
const press=async(id,ms)=>{const box=await button(id).boundingBox();await page.mouse.move(box.x+box.width/2,box.y+box.height/2);await page.mouse.down();await sleep(ms);await page.mouse.up();};
(async()=>{
 const fixture=await ready;browser=await chromium.launch({headless:true,executablePath:process.env.SSH_UI_CHROME||undefined,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 page=await browser.newPage({viewport:{width:1400,height:900}});page.setDefaultTimeout(12000);page.on('pageerror',e=>errors.push(e.message));await page.exposeFunction('desktopRPC',(method,args)=>rpc(method,args));
 await page.addInitScript(methods=>{window.pywebview={api:{}};for(const method of methods)window.pywebview.api[method]=(_token,...args)=>window.desktopRPC(method,args);},methods);
 await page.goto('file://'+fixture.html);await page.waitForFunction(()=>window.SSHUI&&document.querySelector('#bridge-label').textContent==='本地应用已连接');
 const application=await rpc('fixture_request_authorization',['ui-grant']);const id=application.request_id;await refresh();await readyButton(id);
 await check('approval has a one minute deadline and a 0.5 second hold label',async()=>{
  const r=(await rpc('snapshot')).data.requests.find(r=>r.request_id===id);assert.equal(r.approval_timeout_seconds,60);assert(r.approval_remaining_ms>57000&&r.approval_remaining_ms<=60000);assert((await button(id).textContent()).includes('按住 0.5 秒批准'));assert((await button(id).textContent()).match(/\d+s/));
 });
 await check('countdown retreats right to left while approval fill grows left to right',async()=>{
  const countdown=page.locator(`[data-request-id="${id}"] .countdown`),fill=page.locator(`[data-request-id="${id}"] .fill`);
  const before=await countdown.boundingBox();await sleep(650);const after=await countdown.boundingBox();assert(Math.abs(before.x-after.x)<1);assert(after.width<before.width);
  await page.screenshot({path:path.join(output,'approval-countdown.png')});const box=await button(id).boundingBox();await page.mouse.move(box.x+box.width/2,box.y+box.height/2);await page.mouse.down();await sleep(70);const first=await fill.boundingBox();await sleep(110);const second=await fill.boundingBox();assert(Math.abs(first.x-second.x)<1);assert(second.width>first.width);await page.mouse.up();
  assert.equal((await rpc('snapshot')).data.requests.find(r=>r.request_id===id).status,'pending_approval');
 });
 await check('keyboard hold approves a bounded grant after half a second',async()=>{
  await page.locator(`[data-request-id="${id}"]`).click();await page.keyboard.down('a');await sleep(800);await page.keyboard.up('a');await waitStatus(id,'succeeded');const grants=(await rpc('snapshot')).data.authorizations;assert.equal(grants.length,1);assert.equal(grants[0].remaining_uses,3);assert.equal(grants[0].status,'granted');
 });
 await check('settings shows directory commands and use limits and can revoke the grant',async()=>{
  await page.evaluate(()=>window.SSHUI.go('settings'));await page.locator('#temporary-authorizations').waitFor();const section=page.locator('#temporary-authorizations');await page.waitForFunction(()=>document.querySelector('#temporary-authorizations').textContent.includes('printf fixture-check'));const text=await section.textContent();assert(text.includes('/home/fixture/workspace'));assert(text.includes('3/3'));await section.locator('summary').click();await page.screenshot({path:path.join(output,'temporary-authorizations.png')});await section.getByRole('button',{name:'撤销授权',exact:true}).click();await refresh();assert.equal((await rpc('snapshot')).data.authorizations[0].status,'revoked');await page.locator('#drawer-close').click();
 });
 await check('expiry during a hold never grants authorization',async()=>{
  const expired=await rpc('fixture_request_authorization',['ui-expiring']);await refresh();await readyButton(expired.request_id);await rpc('fixture_expire_request',[expired.request_id,.35]);await refresh();await press(expired.request_id,700);await waitStatus(expired.request_id,'expired');assert.equal((await rpc('snapshot')).data.authorizations.length,1);
 });
 await check('ordinary write request also uses a half second hold',async()=>{
  const request=(await rpc('submit_local',['dev','printf fixture-manual','手动审批测试','',300])).data;await refresh();await readyButton(request.request_id);await press(request.request_id,800);await waitStatus(request.request_id,'succeeded');
 });
 await check('authorization settings fit the minimum window width',async()=>{
  await page.setViewportSize({width:960,height:680});await page.evaluate(()=>window.SSHUI.go('settings'));await page.locator('#temporary-authorizations').waitFor();const dimensions=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth}));assert(dimensions.scroll<=dimensions.width+1);
 });
 assert.deepEqual(errors,[]);fs.writeFileSync(path.join(output,'authorization-test-result.json'),JSON.stringify({passed:checks.length,checks,page_errors:errors,engine:await browser.version()},null,2));console.log('AUTHORIZATION UI TESTS PASSED '+checks.length);
})().catch(async e=>{console.error(e);if(page)await page.screenshot({path:path.join(output,'authorization-failure.png')}).catch(()=>{});process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();child.stdin.end();setTimeout(()=>child.kill(),1000).unref();if(fs.existsSync(html))fs.unlinkSync(html);});
