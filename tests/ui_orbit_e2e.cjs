/* Production assets + real request manager; telemetry is deliberately stepped by the test. */
const fs=require('fs'),path=require('path'),os=require('os'),assert=require('assert/strict'),{spawn}=require('child_process'),readline=require('readline');
const {chromium}=require(process.env.PLAYWRIGHT_MODULE||'../frontend/node_modules/playwright');
const root=path.resolve(__dirname,'..'),output=process.env.SSH_UI_OUTPUT||path.join(root,'preview/orbit'),html=path.join(os.tmpdir(),'ssh-orbit-'+require('crypto').randomUUID()+'.html');fs.mkdirSync(output,{recursive:true});
const python=process.env.SSH_UI_PYTHON||path.join(root,'.venv',process.platform==='win32'?'Scripts':'bin',process.platform==='win32'?'python.exe':'python');
const child=spawn(python,['tests/fixture_orbit.py',html],{cwd:root,stdio:['pipe','pipe','pipe']});
let readyResolve,readyReject,next=1,stderr='',browser,page;const checks=[],errors=[],pending=new Map();
const ready=new Promise((resolve,reject)=>{readyResolve=resolve;readyReject=reject;});
child.stderr.on('data',c=>stderr+=c.toString());readline.createInterface({input:child.stdout}).on('line',line=>{try{const x=JSON.parse(line);if(x.ready)readyResolve(x);else{pending.get(x.id)?.resolve(x.result);pending.delete(x.id);}}catch(e){readyReject(e);}});
child.on('error',readyReject);child.on('exit',code=>{if(code){const e=new Error(stderr||'Fixture exited '+code);readyReject(e);for(const p of pending.values())p.reject(e);}});
const rpc=(method,args=[])=>new Promise((resolve,reject)=>{const id=next++;pending.set(id,{resolve,reject});child.stdin.write(JSON.stringify({id,method,args})+'\n');});
const methods=['snapshot','request_detail','test_connection','save_connection','disconnect_connection','answer_prompt','save_settings','begin_review','reject','terminate_request'];
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const check=async(name,fn)=>{await fn();checks.push(name);console.log('PASS '+name);};
const stage=async expected=>page.waitForFunction(expected=>document.querySelector('.orbit-panel')?.dataset.stage===expected,expected);
const state=async expected=>page.waitForFunction(expected=>document.querySelector('.orbit-panel')?.dataset.state===expected,expected);
const title=()=>page.locator('.orbit-heading h2').textContent();
const advance=async values=>{await rpc('fixture_advance',[values]);const s=(await rpc('snapshot')).data.requests[0];await page.waitForFunction(seq=>Number(document.querySelector('.orbit-panel')?.dataset.seq)===seq,s.connection_event_seq);};
const emit=async(event,stage,data={},rest={})=>advance({event,stage,data,...rest});
const start=async()=>{
 await rpc('disconnect_connection',['dev']);await page.evaluate(()=>window.SSHUI.go('connections'));
 await page.locator('[data-action="test-connection"][data-id="dev"]').click();
 await page.waitForSelector('#drawer',{state:'detached'});await stage('dns');await state('active');
};
const finish=async(code,at='tcp')=>{await emit('connection_failed',at,{code},{finish:code});await state('failed');};
const capture=async name=>{await sleep(450);await page.screenshot({path:path.join(output,name+'.png')});};
const fingerprint=JSON.parse(fs.readFileSync(path.join(root,'frontend/tests/fixtures/fingerprint.json'))).fingerprint;
const meta={server_version:'SSH-2.0-OpenSSH_9.9',client_version:'SSH-2.0-paramiko_4.0.0',kex:'curve25519-sha256@libssh.org',cipher_out:'aes128-ctr',cipher_in:'aes128-ctr',key_type:'ssh-ed25519',fingerprint};
(async()=>{
 const fixture=await ready;browser=await chromium.launch({headless:true,executablePath:process.env.SSH_UI_CHROME||undefined,args:['--no-sandbox','--disable-gpu','--disable-dev-shm-usage']});
 page=await browser.newPage({viewport:{width:1400,height:900}});page.setDefaultTimeout(10000);page.on('pageerror',e=>errors.push(e.message));
 await page.exposeFunction('desktopRPC',(method,args)=>rpc(method,args));
 await page.addInitScript(methods=>{window.pywebview={api:{}};for(const method of methods)window.pywebview.api[method]=(_token,...args)=>window.desktopRPC(method,args);},methods);
 await page.goto('file://'+fixture.html);await page.waitForFunction(()=>window.SSHUI&&document.querySelector('#bridge-label').textContent==='本地应用已连接');
 await check('test connection opens the orbital scene; a stalled TCP never advances',async()=>{
  await start();await emit('dns_resolved','dns',{address_count:1});await emit('tcp_started','tcp',{address:'192.0.2.10',port:22});
  const seq=await page.locator('.orbit-panel').getAttribute('data-seq'),before=await page.locator('.orbit-time').textContent();await sleep(2200);
  assert.equal(await page.locator('.orbit-panel').getAttribute('data-stage'),'tcp');assert.equal(await page.locator('.orbit-panel').getAttribute('data-seq'),seq);assert.notEqual(await page.locator('.orbit-time').textContent(),before);await capture('orbit-tcp');
 });
 await check('sequence-only updates refresh negotiated algorithms and untrusted star map',async()=>{
  await emit('tcp_connected','tcp');await emit('banner_received','ssh_banner',{server_version:meta.server_version});await emit('key_exchange_started','key_exchange');
  await emit('algorithms_negotiated','key_exchange',{kex:meta.kex,cipher_out:meta.cipher_out,cipher_in:meta.cipher_in});assert((await page.locator('.orbit-facts').textContent()).includes(meta.kex));
  await emit('host_key_received','host_key',{fingerprint,key_type:meta.key_type});assert.equal(await page.locator('.orbit-panel .fingerprint-art.unverified').count(),1);
  assert.equal(await page.locator('.orbit-stages [data-stage="host_key"].done').count(),0);await capture('orbit-fingerprint');
 });
 await check('host key constellation never accepts trust without a local user action',async()=>{
  await emit('host_key_confirmation_required','host_key');await rpc('fixture_ask_key',[fingerprint]);await page.getByRole('heading',{name:'确认新的主机指纹'}).waitFor();
  assert.equal(await page.locator('#modal svg[data-fingerprint]').getAttribute('data-fingerprint'),fingerprint);assert.equal(await page.locator('#modal .fingerprint-art.verified').count(),0);
  await capture('orbit-host-key-dialog');await page.getByRole('button',{name:'仅本次会话信任',exact:true}).click();await page.waitForSelector('#modal',{state:'detached'});
  await page.locator('.orbit-panel .fingerprint-art.verified').waitFor();
 });
 await check('successful SSH compresses into a summary and retains the full telemetry',async()=>{
  await emit('authentication_started','authentication');await emit('authenticated','authentication',{method:'publickey'});await emit('connected','connected',meta,{finish:'succeeded'});await state('connected');
  assert.equal(await page.locator('.orbit-panel.compact').count(),1);await page.getByRole('button',{name:'展开详情',exact:true}).click();
  assert.equal(await page.locator('.orbit-stages .done').count(),7);await page.locator('.orbit-panel .connection-telemetry summary').click();assert(await page.locator('[data-event="algorithms_negotiated"]').isVisible());
  await capture('orbit-connected');await page.getByRole('button',{name:'收起',exact:true}).click();
 });
 await check('reuse bypasses a staged replay and disconnect keeps an explicit historical label',async()=>{
  await start();await emit('connection_reused','connected',meta,{attempt:0,finish:'succeeded'});await state('reused');assert.match(await title(),/复用/);
  await page.getByRole('button',{name:'展开详情',exact:true}).click();assert.equal(await page.locator('.orbit-stages').count(),0);
  await rpc('disconnect_connection',['dev']);await page.getByText('此为上次握手记录，当前连接已断开。').waitFor();
 });
 await check('timeout and refusal preserve the failed phase and never show connected',async()=>{
  for(const [code,label] of [['timeout','连接超时'],['connection_refused','连接被拒绝']]){await start();await emit('tcp_started','tcp');await finish(code);assert.equal(await title(),label);assert.equal(await page.locator('.orbit-panel').getAttribute('data-stage'),'tcp');await capture('orbit-'+code);}
 });
 await check('algorithm mismatch and wrong host key remain distinct failures',async()=>{
  await start();await emit('key_exchange_started','key_exchange');await finish('algorithm_mismatch','key_exchange');assert.equal(await title(),'算法无交集');
  await start();await emit('host_key_received','host_key',{fingerprint,key_type:'ssh-ed25519'});await emit('connection_failed','host_key',{code:'host_key_mismatch',fingerprint,expected_fingerprint:'SHA256:'+'A'.repeat(43)},{finish:'mismatch'});
  assert.equal(await title(),'主机指纹不符');assert.equal(await page.locator('.orbit-panel .fingerprint-art.verified').count(),0);assert((await page.locator('.orbit-facts').textContent()).includes('预期指纹'));await capture('orbit-host-key-mismatch');
 });
 await check('retry clears identity and trust from the failed attempt',async()=>{
  await start();await emit('host_key_verified','host_key',meta);await emit('authentication_method_failed','authentication',{method:'password'});await state('active');
  await emit('attempt_started','connecting',{}, {attempt:2});assert.equal(await page.locator('.orbit-panel .fingerprint-art').count(),0);assert.equal(await page.locator('.orbit-panel').getAttribute('data-attempt'),'2');await finish('authentication_failed','authentication');
 });
 await check('jump completion stays active until the target authenticates',async()=>{
  await start();await emit('connected','connected',meta,{context:{role:'jump',host_alias:'bastion',hop_count:2}});await state('active');assert.match(await title(),/等待下一跳/);
  await emit('jump_channel_started','tcp',{}, {context:{role:'target',host_alias:'dev',hop_index:2,hop_count:2,via_host_alias:'bastion'}});
  assert.equal(await page.locator('.orbit-panel .fingerprint-art').count(),0);assert.equal(await page.locator('.orbit-stages [data-stage="dns"].done').count(),0);await capture('orbit-jump');await finish('timeout');
 });
 await check('960px viewport at 130% text and reduced motion preserves controls',async()=>{
  await start();await emit('host_key_received','host_key',meta);await page.setViewportSize({width:960,height:680});await page.emulateMedia({reducedMotion:'reduce'});
  await page.evaluate(()=>document.documentElement.style.setProperty('--font-scale','1.3'));await page.locator('.orbit-panel .connection-telemetry summary').click();
  const fit=await page.evaluate(()=>{const p=document.querySelector('.orbit-panel'),r=p.getBoundingClientRect();return {page:document.documentElement.scrollWidth<=innerWidth+1,panel:p.scrollWidth<=p.clientWidth+1,bottom:r.bottom<=innerHeight-29};});assert.deepEqual(fit,{page:true,panel:true,bottom:true});
  const layout=await page.evaluate(()=>{const r=document.querySelector('.orbit-panel').getBoundingClientRect(),cmd=document.querySelector('.orbit-command').getBoundingClientRect();return {command:cmd.bottom<=r.bottom,clearOfNodes:[...document.querySelectorAll('.node')].every(el=>el.getBoundingClientRect().bottom<r.top)};});assert.deepEqual(layout,{command:true,clearOfNodes:true});
  assert(await page.locator('.orbit-panel .connection-telemetry summary').isVisible());await capture('orbit-small-window');
  await rpc('save_settings',[{ui:{effects:'off',motion_enabled:false,scale_percent:130}}]);await page.waitForFunction(()=>document.body.classList.contains('fx-off'));await sleep(200);
  const a=await page.locator('#scene').evaluate(c=>c.toDataURL());await sleep(750);const b=await page.locator('#scene').evaluate(c=>c.toDataURL());assert.equal(a,b);await finish('timeout','host_key');
 });
 await check('post-SSH diagnostics fail independently and request history retains telemetry',async()=>{
  await page.setViewportSize({width:1400,height:900});await page.evaluate(()=>document.documentElement.style.setProperty('--font-scale','1'));
  await start();await emit('connected','connected',meta,{finish:'sftp_failed'});await state('connected');await page.getByText('SSH 握手已成功，后续连接诊断未通过；请查看请求详情。').waitFor();
  await page.getByRole('button',{name:'请求详情 ↗',exact:true}).click();await page.locator('#request-detail .connection-telemetry summary').waitFor();await page.locator('#request-detail .connection-telemetry summary').click();assert(await page.locator('#request-detail [data-event="connected"]').isVisible());
 });
 assert.deepEqual(errors,[]);fs.writeFileSync(path.join(output,'ui-orbit-result.json'),JSON.stringify({passed:checks.length,checks,page_errors:errors,engine:await browser.version()},null,2));console.log('ORBIT UI TESTS PASSED '+checks.length);
})().catch(async e=>{console.error(e);if(page){await page.screenshot({path:path.join(output,'failure.png')}).catch(()=>{});fs.writeFileSync(path.join(output,'failure-details.json'),JSON.stringify({checks,errors,message:String(e)},null,2));}process.exitCode=1;}).finally(async()=>{if(browser)await browser.close();child.stdin.end();setTimeout(()=>child.kill(),1000).unref();if(fs.existsSync(html))fs.unlinkSync(html);});
