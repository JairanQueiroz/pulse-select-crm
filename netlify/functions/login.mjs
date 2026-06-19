import {env,normalizePassword,safeEqual,readValue,json,createSessionCookie,createRecoveryCookie,clearCookie,RECOVERY_COOKIE} from './_auth.mjs';
export default async function(request){
  try{
    const value=await readValue(request);
    if(safeEqual(normalizePassword(value),normalizePassword(env('PULSE_ACCESS_PASSWORD')))){
      return json({authenticated:true},200,[createSessionCookie(request),clearCookie(request,RECOVERY_COOKIE)]);
    }
    return json({authenticated:false,next:'birthday'},401,[createRecoveryCookie(request,'birthday')]);
  }catch(error){
    const status=Number(error.status)||500;
    return json({authenticated:false,message:status===500?'Configuração de segurança indisponível.':'Não foi possível validar o acesso.'},status);
  }
}
export const config={path:'/api/login',method:'POST',rateLimit:{windowLimit:8,windowSize:60,aggregateBy:['ip','domain']}};
