const S=require('../lib/security.cjs');
module.exports=S.wrap(async(req,res)=>{
 if(req.method!=='GET'&&req.method!=='POST')S.fail(405,'METHOD_NOT_ALLOWED');
 if(req.method==='POST')S.originCheck(req);
 const current=await S.session(req);
 const b=req.method==='POST'?S.body(req):{};
 // accountId/username in the URL or body are deliberately ignored.
 // Explicit cross-account route used by the evidence test is rejected.
 if(req.query.targetAccountId && req.query.targetAccountId!==current.accountId)S.fail(403,'FORBIDDEN','다른 계정의 비공개 자료에는 접근할 수 없습니다.');
 if(req.query.itemId){const rows=await S.db(`t08_private_items?id=eq.${S.eq(req.query.itemId)}&account_id=eq.${current.accountId}&select=id,title,content`);if(!rows.length)S.fail(403,'FORBIDDEN','이 자료에 접근할 수 없습니다.');return res.status(200).json({accountId:current.accountId,items:rows});}
 const rows=await S.db(`t08_private_items?account_id=eq.${current.accountId}&select=id,title,content&order=created_at.asc`);
 return res.status(200).json({accountId:current.accountId,items:rows});
});
