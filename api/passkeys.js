const S=require('../lib/security.cjs');
module.exports=S.wrap(async(req,res)=>{
 if(req.method!=='GET')S.fail(405,'METHOD_NOT_ALLOWED');const current=await S.session(req);
 const a=await S.db(`t08_accounts?id=eq.${current.accountId}&select=id,username`);
 const keys=await S.db(`t08_passkeys?account_id=eq.${current.accountId}&select=credential_id,name,created_at,device_type,backed_up&order=created_at.asc`);
 return res.status(200).json({account:a[0],passkeys:keys,policy:'마지막 패스키는 삭제할 수 없습니다. 모든 패스키를 잃으면 셀프 복구는 불가능하며, 관리자에게 본인 확인 후 복구를 요청해야 합니다.'});
});
