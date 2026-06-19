import {readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {isAuthenticated,htmlResponse,redirect,clearCookie,SESSION_COOKIE} from './_auth.mjs';

let cachedHtml;
async function loadHtml(){
  if(cachedHtml) return cachedHtml;
  const candidates=[
    path.join(process.cwd(),'private','crm.html'),
    fileURLToPath(new URL('../../private/crm.html',import.meta.url))
  ];
  for(const candidate of candidates){
    try{cachedHtml=await readFile(candidate,'utf8');return cachedHtml}catch{}
  }
  throw new Error('Arquivo privado do CRM não encontrado.');
}
export default async function(request){
  if(!isAuthenticated(request)) return redirect('/',302,[clearCookie(request,SESSION_COOKIE)]);
  try{return htmlResponse(await loadHtml());}
  catch{return htmlResponse('<h1>CRM indisponível</h1>',500);}
}
export const config={path:'/app',method:'GET',rateLimit:{windowLimit:120,windowSize:60,aggregateBy:['ip','domain']}};
