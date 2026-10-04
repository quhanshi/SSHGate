import {build} from 'vite';
import {mkdir, readFile, writeFile, readdir,rename,stat,utimes} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import path from 'node:path';
const root=path.dirname(fileURLToPath(import.meta.url));
await build({root, configFile:false, define:{'process.env.NODE_ENV':'"production"'}, build:{outDir:'dist', emptyOutDir:true, target:'es2020', cssCodeSplit:false, sourcemap:false, lib:{entry:path.join(root,'src/main.tsx'), name:'SSHGateUI', formats:['iife'], fileName:()=> 'app.js'}, rollupOptions:{output:{inlineDynamicImports:true,assetFileNames:'app.[ext]'}}}});
const destination=path.resolve(root,'../ssh_gate/frontend');
await mkdir(destination,{recursive:true});
const atomicWrite=async(name,data)=>{const target=path.join(destination,name);const old=await stat(target).catch(()=>null);await writeFile(target+'.next',data);await rename(target+'.next',target);const modified=new Date(Math.max(Date.now(),old?.mtimeMs||0)+1000);await utimes(target,modified,modified);};
const files=await readdir(path.join(root,'dist'));
const css=files.find(f=>f.endsWith('.css'));
if(!css) throw new Error('CSS bundle is missing');
const js=await readFile(path.join(root,'dist/app.js'),'utf8');
// Production runs in an inline WebView document; no HTTP server or external asset loads.
await atomicWrite('app.js',js.replace(/<\/script/gi,'<\\/script'));
await atomicWrite('app.css',await readFile(path.join(root,'dist',css)));
await atomicWrite('index.html',`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline' 'unsafe-eval'; style-src 'unsafe-inline'; img-src data:; font-src 'none'; connect-src 'none'; frame-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'"><title>SSH Gate</title><style>/*__APP_CSS__*/</style></head><body><div id="root"></div><script>/*__APP_JS__*/</script></body></html>`);
if(!(await readFile(path.join(destination,'index.html'),'utf8')).includes('id="root"'))throw new Error('React root was not written');
console.log('WebView assets updated: '+destination+' (backend unchanged)');
