const S=require('../lib/security.cjs');
const {generateRegistrationOptions,verifyRegistrationResponse,generateAuthenticationOptions,verifyAuthenticationResponse}=require('@simplewebauthn/server');
module.exports=S.wrap(async(req,res)=>{
 if(req.method!=='POST')S.fail(405,'METHOD_NOT_ALLOWED');
 S.originCheck(req);const b=S.body(req);const c=S.config();const action=req.query.action;
 if(action==='register-options'){
  let a,context;const current=await S.session(req,false);
  if(current){const rows=await S.db(`t08_accounts?id=eq.${current.accountId}&select=*`);a=rows[0];context={sessionHash:current.tokenHash};}
  else{a=await S.account(b.username);if(typeof b.enrollmentToken!=='string'||a.enrolled_at||!a.enrollment_token_hash||S.hash(b.enrollmentToken.trim())!==a.enrollment_token_hash||(!Number.isFinite(Date.parse(a.enrollment_expires_at))||Date.parse(a.enrollment_expires_at)<=Date.now()))S.fail(403,'ENROLLMENT_REJECTED','등록권이 올바르지 않거나 만료되었습니다.');context={enrollmentHash:a.enrollment_token_hash};}
  if(typeof b.name!=='string'||!b.name.trim()||b.name.length>80)S.fail(400,'INVALID_NAME','패스키 이름을 1~80자로 입력해 주세요.');
  context.name=b.name.trim();const keys=await S.db(`t08_passkeys?account_id=eq.${a.id}&select=credential_id,transports`);
  const options=await generateRegistrationOptions({rpName:'나만의 작업실',rpID:c.rpID,userID:new TextEncoder().encode(a.id),userName:a.username,attestationType:'none',supportedAlgorithmIDs:[-7,-257],excludeCredentials:keys.map(k=>({id:k.credential_id,transports:k.transports})),authenticatorSelection:{residentKey:'required',userVerification:'required'}});
  return res.status(200).json(await S.challenge(req,res,a,'registration',options,context));
 }
 if(action==='register-verify'){
  const ch=await S.consume(req,b.challengeId,'registration');
  let sessionHash=null;
  if(ch.context.sessionHash){const current=await S.session(req);if(current.accountId!==ch.account_id||current.tokenHash!==ch.context.sessionHash)S.fail(403,'AUTHORIZATION_REJECTED');sessionHash=current.tokenHash;}
  let v;try{v=await verifyRegistrationResponse({response:b.credential,expectedChallenge:ch.challenge,expectedOrigin:c.origin,expectedRPID:c.rpID,requireUserVerification:true});}catch{S.fail(400,'REGISTRATION_REJECTED','패스키 등록 응답 검증에 실패했습니다.');}
  if(!v.verified||!v.registrationInfo)S.fail(400,'REGISTRATION_REJECTED');
  const {credential:k,credentialDeviceType,credentialBackedUp}=v.registrationInfo;
  await S.db('rpc/t08_finish_registration','POST',{p_account:ch.account_id,p_enrollment_hash:ch.context.enrollmentHash||null,p_session_hash:sessionHash,p_credential:k.id,p_public_key:Buffer.from(k.publicKey).toString('base64url'),p_counter:k.counter,p_name:ch.context.name,p_transports:k.transports||[],p_device_type:credentialDeviceType,p_backed_up:credentialBackedUp});
  return res.status(201).json({verified:true,credentialId:k.id,name:ch.context.name,publicKeyStored:true,message:'패스키가 등록되었습니다. 패스키 로그인 버튼을 눌러 주세요.'});
 }
 if(action==='login-options'){
  const a=await S.account(b.username);const keys=await S.db(`t08_passkeys?account_id=eq.${a.id}&select=credential_id,transports`);
  if(!keys.length)S.fail(403,'NO_PASSKEY','등록된 패스키가 없습니다. 모든 패스키를 잃었다면 관리자에게 복구를 요청해 주세요.');
  const options=await generateAuthenticationOptions({rpID:c.rpID,userVerification:'required',allowCredentials:keys.map(k=>({id:k.credential_id,transports:k.transports}))});
  return res.status(200).json(await S.challenge(req,res,a,'authentication',options));
 }
 if(action==='login-verify'){
  const ch=await S.consume(req,b.challengeId,'authentication');
  if(typeof b.credential?.id!=='string')S.fail(400,'INVALID_CREDENTIAL');
  const keys=await S.db(`t08_passkeys?account_id=eq.${ch.account_id}&credential_id=eq.${S.eq(b.credential.id)}&select=*`);
  if(!keys.length)S.fail(403,'CREDENTIAL_REJECTED','이 계정의 패스키가 아니거나 삭제된 패스키입니다.');const k=keys[0];
  if(b.credential.response?.userHandle && b.credential.response.userHandle!==Buffer.from(ch.account_id).toString('base64url'))S.fail(403,'CREDENTIAL_REJECTED');
  let v;try{v=await verifyAuthenticationResponse({response:b.credential,expectedChallenge:ch.challenge,expectedOrigin:c.origin,expectedRPID:c.rpID,requireUserVerification:true,credential:{id:k.credential_id,publicKey:new Uint8Array(Buffer.from(k.public_key,'base64url')),counter:Number(k.counter),transports:k.transports}});}catch{S.fail(403,'SIGNATURE_REJECTED','패스키 서명 검증에 실패했습니다.');}
  if(!v.verified)S.fail(403,'SIGNATURE_REJECTED');
  const token=S.random();await S.db('rpc/t08_finish_login','POST',{p_account:ch.account_id,p_credential:k.credential_id,p_old_counter:Number(k.counter),p_new_counter:v.authenticationInfo.newCounter,p_token_hash:S.hash(token)});
  const old=S.cookie(req,'__Host-t08_session');if(old)await S.db(`t08_sessions?token_hash=eq.${S.hash(old)}`,'PATCH',{revoked_at:new Date().toISOString()});
  S.setCookie(res,'__Host-t08_session',token,3600);return res.status(200).json({verified:true,message:'패스키 로그인에 성공했습니다.'});
 }
 if(action==='cancel'){
  await S.consume(req,b.challengeId,b.purpose==='authentication'?'authentication':'registration');return res.status(200).json({cancelled:true,message:'취소되었습니다. 패스키는 저장되지 않았습니다.'});
 }
 if(action==='logout'){
  const token=S.cookie(req,'__Host-t08_session');if(token)await S.db(`t08_sessions?token_hash=eq.${S.hash(token)}`,'PATCH',{revoked_at:new Date().toISOString()});
  S.setCookie(res,'__Host-t08_session','',0);return res.status(200).json({loggedOut:true});
 }
 if(action==='delete'){
  const current=await S.session(req);if(typeof b.credentialId!=='string')S.fail(400,'INVALID_CREDENTIAL');
  await S.db('rpc/t08_delete_passkey','POST',{p_account:current.accountId,p_credential:b.credentialId,p_session_hash:current.tokenHash});
  S.setCookie(res,'__Host-t08_session','',0);return res.status(200).json({deleted:true,loggedOut:true,message:'삭제되었습니다. 남은 패스키로 다시 로그인해 주세요.'});
 }
 S.fail(404,'UNKNOWN_ACTION');
});
