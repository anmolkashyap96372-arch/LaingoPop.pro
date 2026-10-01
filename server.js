const express=require('express'),fs=require('fs'),path=require('path'),crypto=require('crypto'),https=require('https'),http=require('http');
const app=express();app.use(express.json());app.set('trust proxy',true);

const ADMIN_KEY=process.env.ADMIN_KEY||'change-me';
const FILE=process.env.DATA_FILE||path.join(__dirname,'data.json');
const VAPID_PUBLIC=process.env.VAPID_PUBLIC||'';
const VAPID_PRIVATE=process.env.VAPID_PRIVATE||'';
const VAPID_SUBJECT=process.env.VAPID_SUBJECT||'mailto:admin@laingopop.com';
const DAYS={yearly:365,monthly:30,week:7};

let db={grants:[],subs:[]};
try{db=JSON.parse(fs.readFileSync(FILE,'utf8'))}catch(e){}
if(!db.grants)db.grants=[];if(!db.subs)db.subs=[];
const save=()=>{try{fs.writeFileSync(FILE,JSON.stringify(db))}catch(e){}};
const ipOf=r=>(r.headers['x-nf-client-connection-ip']||r.headers['cf-connecting-ip']||(r.headers['x-forwarded-for']||'').split(',')[0]||r.ip||'').trim();
const norm=s=>String(s||'').trim().toUpperCase();
const live=g=>g.expiresAt>Date.now();
const adminOnly=(q,s,n)=>q.headers['x-admin-key']===ADMIN_KEY?n():s.status(401).json({error:'bad key'});
const b64url=b=>Buffer.from(b).toString('base64').replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');

// ── VAPID helpers (no npm dep) ────────────────────────────────────────────────
function vapidJwt(audience){
  const header=b64url(JSON.stringify({typ:'JWT',alg:'ES256'}));
  const payload=b64url(JSON.stringify({aud:audience,exp:Math.floor(Date.now()/1000)+3600,sub:VAPID_SUBJECT}));
  const unsigned=`${header}.${payload}`;
  const privDer=Buffer.from(VAPID_PRIVATE,'base64');
  let privKey;
  try{
    // raw 32-byte key -> pkcs8 der
    const pkcs8=Buffer.concat([Buffer.from('308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042','hex'),privDer,Buffer.from('a144034200','hex'),Buffer.from(VAPID_PUBLIC,'base64')]);
    privKey=crypto.createPrivateKey({key:pkcs8,format:'der',type:'pkcs8'});
  }catch(e){privKey=crypto.createPrivateKey({key:Buffer.from(VAPID_PRIVATE,'base64'),format:'der',type:'pkcs8'})}
  const sig=crypto.sign('sha256',Buffer.from(unsigned),{key:privKey,dsaEncoding:'ieee-p1363'});
  return `${unsigned}.${b64url(sig)}`;
}
function sendPush(sub,payload){
  return new Promise((ok,fail)=>{
    if(!VAPID_PUBLIC||!VAPID_PRIVATE)return fail(new Error('No VAPID keys'));
    const ep=new URL(sub.endpoint);
    const audience=`${ep.protocol}//${ep.host}`;
    const jwt=vapidJwt(audience);
    const auth=`vapid t=${jwt},k=${VAPID_PUBLIC}`;
    const body=Buffer.from(typeof payload==='string'?payload:JSON.stringify(payload));
    const opts={hostname:ep.hostname,port:ep.port||443,path:ep.pathname+ep.search,method:'POST',headers:{'Content-Type':'application/octet-stream','Content-Length':body.length,'Authorization':auth,'TTL':'86400'}};
    const req=(ep.protocol==='https:'?https:http).request(opts,r=>{r.resume();ok(r.statusCode)});
    req.on('error',fail);req.write(body);req.end();
  });
}

// ── Status (app calls on open) ────────────────────────────────────────────────
app.get('/api/status',(q,s)=>{
  const ref=norm(q.query.ref),ip=ipOf(q);
  const g=db.grants.filter(live).filter(x=>(x.ref&&x.ref===ref)||(x.ip&&x.ip===ip)).sort((a,b)=>b.expiresAt-a.expiresAt)[0];
  s.set('Cache-Control','no-store');
  s.json(g?{pro:true,plan:g.plan,expiresAt:g.expiresAt}:{pro:false});
});

// ── Push config (app fetches VAPID public key) ────────────────────────────────
app.get('/api/push/config',(q,s)=>s.json({publicKey:VAPID_PUBLIC}));

// ── Push subscribe ────────────────────────────────────────────────────────────
app.post('/api/push/subscribe',(q,s)=>{
  const{endpoint,keys,ref}=q.body||{};
  if(!endpoint)return s.status(400).json({error:'no endpoint'});
  const existing=db.subs.findIndex(x=>x.endpoint===endpoint);
  const rec={endpoint,keys,ref:norm(ref),updatedAt:Date.now()};
  if(existing>=0)db.subs[existing]=rec;else db.subs.push(rec);
  save();s.json({ok:true});
});

// ── Push unsubscribe ──────────────────────────────────────────────────────────
app.post('/api/push/unsubscribe',(q,s)=>{
  const{endpoint}=q.body||{};
  db.subs=db.subs.filter(x=>x.endpoint!==endpoint);
  save();s.json({ok:true});
});

// ── Push test (app's own test button) ────────────────────────────────────────
app.post('/api/push/test',async(q,s)=>{
  const{endpoint}=q.body||{};
  const sub=db.subs.find(x=>x.endpoint===endpoint);
  if(!sub)return s.status(404).json({error:'not found'});
  try{await sendPush(sub,{title:'LaingoPop Test',body:'Push is working! 🎉'});s.json({ok:true})}
  catch(e){s.status(500).json({error:e.message})}
});

// ── Admin panel ───────────────────────────────────────────────────────────────
app.get('/admin',(q,s)=>s.sendFile(path.join(__dirname,'public','admin.html')));
app.get('/api/admin/list',adminOnly,(q,s)=>s.json(db.grants.slice().reverse()));
app.get('/api/admin/myip',adminOnly,(q,s)=>s.json({ip:ipOf(q)}));
app.get('/api/admin/subs',adminOnly,(q,s)=>s.json(db.subs));

app.post('/api/admin/grant',adminOnly,(q,s)=>{
  const{plan,note}=q.body,ref=norm(q.body.ref),ip=String(q.body.ip||'').trim();
  const days=Number(q.body.days)||DAYS[plan];
  if(!days||!DAYS[plan]||(!ref&&!ip))return s.status(400).json({error:'plan + (ref or ip) required'});
  const old=db.grants.filter(live).find(x=>(ref&&x.ref===ref)||(ip&&x.ip===ip));
  const start=old?old.expiresAt:Date.now();
  const g={id:Date.now().toString(36),ref,ip,plan,note:note||'',createdAt:Date.now(),expiresAt:start+days*864e5};
  if(old){Object.assign(old,{expiresAt:g.expiresAt,plan,note:g.note});if(ref)old.ref=ref;if(ip)old.ip=ip;save();return s.json(old)}
  db.grants.push(g);save();s.json(g);
});

app.post('/api/admin/revoke',adminOnly,(q,s)=>{const g=db.grants.find(x=>x.id===q.body.id);if(g)g.expiresAt=0;save();s.json({ok:true})});

// ── Admin send push ───────────────────────────────────────────────────────────
app.post('/api/admin/push',adminOnly,async(q,s)=>{
  const{ref,title,body,all}=q.body||{};
  let targets=all?db.subs:db.subs.filter(x=>x.ref===norm(ref));
  if(!targets.length)return s.status(404).json({error:'No subscriptions found'});
  const msg={title:title||'LaingoPop Reminder',body:body||'Ek reminder aaya hai!',data:{url:'./?action=quiz&alarm=1'}};
  const results=await Promise.allSettled(targets.map(sub=>sendPush(sub,msg)));
  const sent=results.filter(r=>r.status==='fulfilled').length;
  s.json({sent,total:targets.length});
});

app.listen(process.env.PORT||3000);
