import {startRegistration,startAuthentication,browserSupportsWebAuthn} from '@simplewebauthn/browser';
const $=id=>document.getElementById(id);let loggedIn=false,busy=false;
function message(text){$('workshop-status').textContent=text;}
async function api(action,data){const r=await fetch('/api/passkey?action='+action,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw new Error(j.message||j.error);return j;}
async function refresh(){
 const r=await fetch('/api/passkeys',{cache:'no-store'});
 if(r.status===401){loggedIn=false;$('private-content').replaceChildren();$('key-list').replaceChildren();$('signed-in').hidden=true;$('signed-out').hidden=false;return;}
 if(!r.ok)throw new Error('서버 연결을 확인해 주세요.');
 const j=await r.json();loggedIn=true;$('signed-in').hidden=false;$('signed-out').hidden=true;$('account-label').textContent=j.account.username;
 $('key-list').replaceChildren();for(const k of j.passkeys){const li=document.createElement('li');const label=document.createElement('span');label.textContent=`${k.name} · ${new Date(k.created_at).toLocaleString('ko-KR')} · ID ${k.credential_id.slice(0,12)}… `;li.append(label);const btn=document.createElement('button');btn.textContent='삭제';btn.disabled=j.passkeys.length===1;btn.addEventListener('click',()=>run(async()=>{if(!confirm('이 패스키를 삭제하고 모든 로그인 세션을 종료할까요?'))return;const out=await api('delete',{credentialId:k.credential_id});await refresh();message(out.message);}));li.append(btn);$('key-list').append(li);}
 $('key-policy').textContent=j.policy;
 const data=await fetch('/api/private',{cache:'no-store'});if(!data.ok){await refreshIfUnauthorized(data);return;}const contents=await data.json();$('private-content').replaceChildren();for(const item of contents.items){const article=document.createElement('article');const h=document.createElement('h3');h.textContent=item.title;const p=document.createElement('p');p.textContent=item.content;article.append(h,p);$('private-content').append(article);}
}
async function refreshIfUnauthorized(r){if(r.status===401){loggedIn=false;$('private-content').replaceChildren();$('key-list').replaceChildren();$('signed-in').hidden=true;$('signed-out').hidden=false;message('세션이 만료되었습니다. 다시 로그인해 주세요.');}else throw new Error('비공개 자료를 가져오지 못했습니다.');}
async function run(fn){if(busy)return;busy=true;for(const id of ['first-register','login','add-key','logout'])$(id).disabled=true;try{await fn();}catch(e){message(e.message);}finally{busy=false;for(const id of ['first-register','login','add-key','logout'])$(id).disabled=false;}}
async function register(){
 const name=loggedIn?$('extra-name').value:$('first-name').value;
 const options=await api('register-options',{username:$('username').value,enrollmentToken:loggedIn?undefined:$('enrollment-token').value,name});
 $('enrollment-token').value='';let credential;
 try{credential=await startRegistration({optionsJSON:options.options});}catch(e){try{await api('cancel',{challengeId:options.challengeId,purpose:'registration'});}catch{}message(e.name==='NotAllowedError'?'등록을 취소했습니다. 패스키는 저장되지 않았습니다.':'등록하지 못했습니다. 다른 기기 또는 저장 위치를 선택해 다시 시도해 주세요.');return;}
 const j=await api('register-verify',{challengeId:options.challengeId,credential});await refresh();message(j.message);
}
$('first-register').addEventListener('click',()=>run(register));$('add-key').addEventListener('click',()=>run(register));
$('login').addEventListener('click',()=>run(async()=>{const options=await api('login-options',{username:$('username').value});let credential;try{credential=await startAuthentication({optionsJSON:options.options});}catch{try{await api('cancel',{challengeId:options.challengeId,purpose:'authentication'});}catch{}message('로그인을 취소했습니다.');return;}const j=await api('login-verify',{challengeId:options.challengeId,credential});await refresh();message(j.message);}));
$('logout').addEventListener('click',()=>run(async()=>{await api('logout',{});await refresh();message('로그아웃했습니다. 비공개 자료를 숨겼습니다.');}));
if(!browserSupportsWebAuthn())message('이 브라우저는 패스키를 지원하지 않습니다. 지원하는 브라우저로 열어 주세요.');else refresh().catch(e=>message(e.message));
// Recheck expiry/revocation when returning to this tab; do not cache private data.
document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!busy)refresh().catch(e=>message(e.message));});
