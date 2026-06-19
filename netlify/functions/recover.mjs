import {env,normalizeBirthday,normalizeName,safeEqual,readValue,json,createSessionCookie,createRecoveryCookie,clearCookie,recoveryStage,RECOVERY_COOKIE} from './_auth.mjs';
export default async function(request){
  try{
    const stage=recoveryStage(request);
    if(!stage) return json({authenticated:false,message:'Sessão de recuperação expirada. Volte ao início.',locked:true},401,[clearCookie(request,RECOVERY_COOKIE)]);
    const value=await readValue(request);
    if(stage==='birthday'){
      if(safeEqual(normalizeBirthday(value),normalizeBirthday(env('PULSE_CHILD_BIRTHDAY')))){
        return json({authenticated:true},200,[createSessionCookie(request),clearCookie(request,RECOVERY_COOKIE)]);
      }
      return json({authenticated:false,next:'grandma'},401,[createRecoveryCookie(request,'grandma')]);
    }
    if(stage==='grandma'){
      if(safeEqual(normalizeName(value),normalizeName(env('PULSE_GRANDMA_NAME')))){
        return json({authenticated:true},200,[createSessionCookie(request),clearCookie(request,RECOVERY_COOKIE)]);
      }
      return json({authenticated:false,message:'Acesso negado. Recarregue a página para tentar novamente.',locked:true},403,[clearCookie(request,RECOVERY_COOKIE)]);
    }
    return json({authenticated:false,message:'Fluxo de recuperação inválido.',locked:true},400,[clearCookie(request,RECOVERY_COOKIE)]);
  }catch(error){
    const status=Number(error.status)||500;
    return json({authenticated:false,message:status===500?'Configuração de segurança indisponível.':'Não foi possível validar o acesso.'},status);
  }
}
export const config={path:'/api/recover',method:'POST',rateLimit:{windowLimit:8,windowSize:60,aggregateBy:['ip','domain']}};
