const $=s=>document.querySelector(s);
const toast=m=>{const t=$('#toast');if(!t)return;t.textContent=m;t.classList.add('show');setTimeout(()=>t.classList.remove('show'),2500)};
const savedKey=()=>localStorage.getItem('derviq_api_key')||'';
const key=()=>$('#key')?.value.trim()||savedKey();
const out=x=>$('#out').textContent=JSON.stringify(x,null,2);
function syncKey(){const k=savedKey();if($('#key')&&!$('#key').value&&k)$('#key').value=k;updateKeyStatus()}
function updateKeyStatus(){const el=$('#keyStatus');if(el)el.textContent=key()?'● API key saved locally':'○ No API key saved'}
function saveKey(){const k=$('#key')?.value.trim()||'';if(!k){localStorage.removeItem('derviq_api_key');updateKeyStatus();toast('API key cleared.');return}localStorage.setItem('derviq_api_key',k);updateKeyStatus();toast('API key saved locally.');}
function clearKey(){localStorage.removeItem('derviq_api_key');if($('#key'))$('#key').value='';updateKeyStatus();toast('API key removed from this browser.');}
async function api(path,opts={}){const h={'Content-Type':'application/json',...(opts.headers||{})};const k=key();if(k)h['X-API-Key']=k;const r=await fetch(path,{...opts,headers:h});const text=await r.text();let d;try{d=JSON.parse(text)}catch{d=text}if(!r.ok)throw new Error(typeof d==='string'?d:JSON.stringify(d));return d}
$('#key')?.addEventListener('input',updateKeyStatus);
$('#saveKey')?.addEventListener('click',saveKey);
$('#clearKey')?.addEventListener('click',clearKey);
$('#form')?.addEventListener('submit',async e=>{e.preventDefault();try{const d=await api('/evaluate',{method:'POST',body:JSON.stringify({agent_id:$('#agent').value.trim(),action:$('#action').value,amount:Number($('#amount').value),context:{risk:Number($('#risk').value)}})});out(d);toast('Policy decision returned.')}catch(e){out({error:e.message});toast('Request rejected or unavailable.')}});
$('#evidenceBtn')?.addEventListener('click',async()=>{try{const d=await api('/evidence/verify');out(d);toast('Evidence verification returned.')}catch(e){out({error:e.message});toast('Verification unavailable.')}});
$('#healthBtn')?.addEventListener('click',health);
async function health(){try{const r=await fetch('/health',{cache:'no-store'});const d=await r.json();$('#status').textContent='LIVE';$('#heroStatus').textContent='LIVE';out(d)}catch(e){$('#status').textContent='OFFLINE';$('#heroStatus').textContent='OFFLINE'}}
document.querySelectorAll('.card,.step,.tl,.panel,.mega>div').forEach(x=>x.classList.add('reveal'));const io=new IntersectionObserver(es=>es.forEach(e=>{if(e.isIntersecting)e.target.classList.add('in')}),{threshold:.08});document.querySelectorAll('.reveal').forEach(x=>io.observe(x));$('#year').textContent=new Date().getFullYear();syncKey();health();
