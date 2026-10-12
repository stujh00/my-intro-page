const {createHash,randomBytes}=require('node:crypto');
class HttpError extends Error {constructor(status,code,message){super(message||code);this.status=status;this.code=code;}}
const fail=(status,code,message)=>{throw new HttpError(status,code,message);};
const hash=s=>createHash('sha256').update(s).digest('hex');
const random=()=>randomBytes(32).toString('base64url');
function config(){
 const {SUPABASE_URL:url,SUPABASE_SERVICE_ROLE_KEY:key,WEBAUTHN_RP_ID:rpID,WEBAUTHN_ORIGIN:origin}=process.env;
 if(!url||!key||!rpID||!origin)fail(503,'SERVER_NOT_CONFIGURED','서버 설정을 확인해 주세요.');
 if(new URL(origin).origin!==origin||new URL(origin).protocol!=='https:'||new URL(origin).hostname!==rpID)fail(503,'SERVER_NOT_CONFIGURED');
 return {url:url.replace(/\/$/,''),key,rpID,origin};
}
function cookie(req,name){const values=(req.headers.cookie||'').split(';').map(x=>x.trim());const found=values.find(x=>x.startsWith(name+'='));return found?found.slice(name.length+1):'';}
function setCookie(res,name,value,maxAge){res.setHeader('Set-Cookie',`${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`);}
function originCheck(req){if(req.headers.origin!==config().origin)fail(403,'ORIGIN_REJECTED','허용되지 않은 사이트 요청입니다.');}
function body(req){const b=req.body; if(!b||typeof b!=='object'||Array.isArray(b))fail(400,'INVALID_BODY');if(Buffer.byteLength(JSON.stringify(b))>200000)fail(413,'BODY_TOO_LARGE');return b;}
async function db(path,method='GET',data){const c=config();const resp=await fetch(c.url+'/rest/v1/'+path,{method,headers:{apikey:c.key,Authorization:'Bearer '+c.key,'Content-Type':'application/json',Prefer:'return=representation'},body:data===undefined?undefined:JSON.stringify(data),signal:AbortSignal.timeout(12000)});let json;try{json=await resp.json();}catch{json=null;}if(!resp.ok){const msg=json?.message||'';if(/LAST_PASSKEY/.test(msg))fail(409,'LAST_PASSKEY','마지막 패스키는 삭제할 수 없습니다. 모든 패스키를 잃으면 관리자에게 복구를 요청해야 합니다.');if(/ENROLLMENT_REJECTED|SESSION_REJECTED|CREDENTIAL_CHANGED|CREDENTIAL_NOT_FOUND/.test(msg))fail(403,'AUTHORIZATION_REJECTED','등록 또는 로그인 권한이 유효하지 않습니다.');if(resp.status===409)fail(409,'DUPLICATE_CREDENTIAL','이미 등록된 패스키입니다.');fail(503,'DATABASE_UNAVAILABLE','서버 저장소 연결을 확인해 주세요.');}return json;}
const eq=s=>encodeURIComponent(s);
async function session(req,required=true){const token=cookie(req,'__Host-t08_session');if(!/^[A-Za-z0-9_-]{43}$/.test(token)){if(required)fail(401,'AUTH_REQUIRED','패스키 로그인이 필요합니다.');return null;}const tokenHash=hash(token);const rows=await db(`t08_sessions?token_hash=eq.${tokenHash}&revoked_at=is.null&expires_at=gt.${eq(new Date().toISOString())}&select=account_id`);if(!rows?.length){if(required)fail(401,'AUTH_REQUIRED','패스키 로그인이 필요합니다.');return null;}return {accountId:rows[0].account_id,tokenHash};}
async function account(username){if(!['owner-a','tester-b'].includes(username))fail(400,'INVALID_ACCOUNT');const rows=await db(`t08_accounts?username=eq.${eq(username)}&select=*`);if(!rows?.length)fail(404,'ACCOUNT_NOT_FOUND');return rows[0];}
async function challenge(req,res,a,purpose,options,context={}){
 const bind=random();const rows=await db('t08_challenges','POST',{account_id:a.id,purpose,challenge:options.challenge,binding_hash:hash(bind),expires_at:new Date(Date.now()+300000).toISOString(),context});
 setCookie(res,'__Host-t08_challenge',bind,300);return {challengeId:rows[0].id,options};
}
async function consume(req,id,purpose){
 if(typeof id!=='string'||!/^[0-9a-f-]{36}$/.test(id))fail(400,'INVALID_CHALLENGE');
 const bind=cookie(req,'__Host-t08_challenge');if(!bind)fail(400,'CHALLENGE_REJECTED','질문이 만료되었거나 이미 사용되었습니다. 다시 시도해 주세요.');
 // Conditional UPDATE is atomic: only one concurrent request can consume this row.
 const rows=await db(`t08_challenges?id=eq.${eq(id)}&purpose=eq.${purpose}&binding_hash=eq.${hash(bind)}&consumed_at=is.null&expires_at=gt.${eq(new Date().toISOString())}`,'PATCH',{consumed_at:new Date().toISOString()});
 if(!rows?.length)fail(400,'CHALLENGE_REJECTED','질문이 만료되었거나 이미 사용되었습니다. 다시 시도해 주세요.');return rows[0];
}
function wrap(fn){return async(req,res)=>{res.setHeader('Cache-Control','no-store');res.setHeader('X-Content-Type-Options','nosniff');try{await fn(req,res);}catch(e){if(e instanceof HttpError)return res.status(e.status).json({error:e.code,message:e.message});console.error('T08 request failed:',e.name);return res.status(503).json({error:'SERVER_ERROR',message:'서버 처리에 실패했습니다. 설정과 배포 로그를 확인해 주세요.'});}};}
module.exports={HttpError,fail,hash,random,config,cookie,setCookie,originCheck,body,db,eq,session,account,challenge,consume,wrap};
