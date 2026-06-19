import {isAuthenticated,json} from './_auth.mjs';
export default async function(request){ return json({authenticated:isAuthenticated(request)}); }
export const config={path:'/api/session',method:'GET',rateLimit:{windowLimit:60,windowSize:60,aggregateBy:['ip','domain']}};
