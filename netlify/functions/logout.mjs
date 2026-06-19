import {json,clearCookie,SESSION_COOKIE,RECOVERY_COOKIE,validateSameOrigin} from './_auth.mjs';
export default async function(request){
  if(!validateSameOrigin(request)) return json({ok:false},403);
  return json({ok:true},200,[clearCookie(request,SESSION_COOKIE),clearCookie(request,RECOVERY_COOKIE)]);
}
export const config={path:'/api/logout',method:'POST',rateLimit:{windowLimit:20,windowSize:60,aggregateBy:['ip','domain']}};
