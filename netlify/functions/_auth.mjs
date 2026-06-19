import crypto from 'node:crypto';

export const SESSION_COOKIE = 'pulse_session';
export const RECOVERY_COOKIE = 'pulse_recovery';
const SESSION_TTL = 8 * 60 * 60;
const RECOVERY_TTL = 10 * 60;

export function env(name){
  const value=process.env[name];
  if(!value) throw new Error(`Variável obrigatória ausente: ${name}`);
  return value;
}

export function normalizeName(value){
  return String(value??'').trim().toLocaleLowerCase('pt-BR').normalize('NFD').replace(/[\u0300-\u036f]/g,'');
}
export function normalizeBirthday(value){
  return String(value??'').trim().replace(/[.\-]/g,'/').replace(/\s+/g,'');
}
export function normalizePassword(value){ return String(value??'').trim(); }

export function safeEqual(a,b){
  const left=crypto.createHash('sha256').update(String(a)).digest();
  const right=crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(left,right);
}

function secret(){
  const value=env('PULSE_SESSION_SECRET');
  if(value.length<32) throw new Error('PULSE_SESSION_SECRET deve ter no mínimo 32 caracteres.');
  return value;
}
function b64url(value){ return Buffer.from(value).toString('base64url'); }
function signPart(value){ return crypto.createHmac('sha256',secret()).update(value).digest('base64url'); }

export function createToken(kind,data={},ttlSeconds=SESSION_TTL){
  const now=Math.floor(Date.now()/1000);
  const payload=b64url(JSON.stringify({kind,iat:now,exp:now+ttlSeconds,jti:crypto.randomUUID(),...data}));
  return `${payload}.${signPart(payload)}`;
}
export function verifyToken(token,kind){
  if(!token||!token.includes('.')) return null;
  const [payload,signature]=token.split('.',2);
  const expected=signPart(payload);
  const a=Buffer.from(signature); const b=Buffer.from(expected);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b)) return null;
  try{
    const parsed=JSON.parse(Buffer.from(payload,'base64url').toString('utf8'));
    const now=Math.floor(Date.now()/1000);
    if(parsed.kind!==kind||!Number.isFinite(parsed.exp)||parsed.exp<=now) return null;
    return parsed;
  }catch{return null;}
}

export function parseCookies(request){
  const raw=request.headers.get('cookie')||'';
  return Object.fromEntries(raw.split(';').map(v=>v.trim()).filter(Boolean).map(part=>{
    const i=part.indexOf('='); return i<0?[part,'']:[decodeURIComponent(part.slice(0,i)),decodeURIComponent(part.slice(i+1))];
  }));
}
function cookieSecurity(request){ return new URL(request.url).protocol==='https:'?'; Secure':''; }
export function setCookie(request,name,value,maxAge){
  return `${encodeURIComponent(name)}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${cookieSecurity(request)}`;
}
export function clearCookie(request,name){ return `${encodeURIComponent(name)}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${cookieSecurity(request)}`; }
export function createSessionCookie(request){ return setCookie(request,SESSION_COOKIE,createToken('session'),SESSION_TTL); }
export function createRecoveryCookie(request,stage){ return setCookie(request,RECOVERY_COOKIE,createToken('recovery',{stage},RECOVERY_TTL),RECOVERY_TTL); }

export function isAuthenticated(request){
  const cookies=parseCookies(request);
  return Boolean(verifyToken(cookies[SESSION_COOKIE],'session'));
}
export function recoveryStage(request){
  const cookies=parseCookies(request);
  return verifyToken(cookies[RECOVERY_COOKIE],'recovery')?.stage||null;
}

export function securityHeaders(contentType='application/json; charset=utf-8'){
  return {
    'Content-Type':contentType,
    'Cache-Control':'no-store, private, max-age=0',
    'Pragma':'no-cache',
    'X-Content-Type-Options':'nosniff',
    'X-Frame-Options':'DENY',
    'Referrer-Policy':'no-referrer',
    'Permissions-Policy':'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy':'same-origin',
    'Cross-Origin-Resource-Policy':'same-origin'
  };
}
export function json(data,status=200,cookies=[]){
  const headers=new Headers(securityHeaders());
  for(const cookie of cookies) headers.append('Set-Cookie',cookie);
  return new Response(JSON.stringify(data),{status,headers});
}
export function htmlResponse(body,status=200,cookies=[]){
  const headers=new Headers(securityHeaders('text/html; charset=utf-8'));
  headers.set('Content-Security-Policy',"default-src 'self' https: data: blob:; img-src 'self' https://i.postimg.cc data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests");
  for(const cookie of cookies) headers.append('Set-Cookie',cookie);
  return new Response(body,{status,headers});
}
export function redirect(location,status=302,cookies=[]){
  const headers=new Headers(securityHeaders('text/plain; charset=utf-8'));
  headers.set('Location',location);
  for(const cookie of cookies) headers.append('Set-Cookie',cookie);
  return new Response(null,{status,headers});
}

export function validateSameOrigin(request){
  const origin=request.headers.get('origin');
  const expected=new URL(request.url).origin;
  return origin===expected;
}
export async function readValue(request){
  if(!validateSameOrigin(request)) throw Object.assign(new Error('Origem inválida.'),{status:403});
  const type=request.headers.get('content-type')||'';
  if(!type.toLowerCase().startsWith('application/json')) throw Object.assign(new Error('Conteúdo inválido.'),{status:415});
  const length=Number(request.headers.get('content-length')||0);
  if(length>2048) throw Object.assign(new Error('Requisição muito grande.'),{status:413});
  const body=await request.json().catch(()=>null);
  if(!body||typeof body.value!=='string'||body.value.length>120) throw Object.assign(new Error('Entrada inválida.'),{status:400});
  return body.value;
}
