const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = Number(process.env.PORT || 8080);
const ROOT = __dirname;
const PROXY_SECRET = process.env.GISS_PROXY_SECRET || '';

const MIME = {
  '.html':'text/html; charset=utf-8',
  '.js':'application/javascript; charset=utf-8',
  '.css':'text/css; charset=utf-8',
  '.json':'application/json; charset=utf-8',
  '.svg':'image/svg+xml',
  '.png':'image/png',
  '.jpg':'image/jpeg',
  '.jpeg':'image/jpeg',
  '.ico':'image/x-icon',
  '.pdf':'application/pdf',
  '.xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  '.xls':'application/vnd.ms-excel',
  '.csv':'text/csv; charset=utf-8'
};

function sendJson(res, status, body){
  res.writeHead(status, {'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store'});
  res.end(JSON.stringify(body));
}

function readBody(req, limit=8*1024*1024){
  return new Promise((resolve,reject)=>{
    const chunks=[]; let size=0;
    req.on('data', c=>{
      size += c.length;
      if(size>limit){ reject(new Error('Payload muito grande.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', ()=>resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function mtlsRequest({url, method='POST', headers={}, body='', certChain, privateKey}){
  return new Promise((resolve,reject)=>{
    const target = new URL(url);
    if(target.protocol!=='https:') return reject(new Error('Endpoint GISS inválido.'));
    const opts = {
      protocol:'https:',
      hostname:target.hostname,
      port:target.port || 443,
      path:target.pathname + target.search,
      method,
      cert:certChain,
      key:privateKey,
      rejectUnauthorized:true,
      servername:target.hostname,
      headers:{
        ...headers,
        'Content-Length':Buffer.byteLength(body)
      }
    };
    const r=https.request(opts, rr=>{
      const out=[];
      rr.on('data', c=>out.push(c));
      rr.on('end', ()=>resolve({
        status:rr.statusCode || 0,
        headers:rr.headers,
        body:Buffer.concat(out).toString('utf8')
      }));
    });
    r.setTimeout(45000, ()=>r.destroy(new Error('Timeout na conexão com a GISS.')));
    r.on('error', reject);
    if(body) r.write(body);
    r.end();
  });
}

async function handleProxy(req,res){
  if(req.method!=='POST') return sendJson(res,405,{error:'Método inválido'});
  const key=req.headers['x-giss-proxy-key'] || '';
  if(!PROXY_SECRET || key!==PROXY_SECRET) return sendJson(res,401,{error:'Não autorizado'});
  try{
    const raw=await readBody(req);
    const b=JSON.parse(raw || '{}');
    if(!b.url || !b.certChain || !b.privateKey) return sendJson(res,400,{error:'Dados mTLS incompletos'});
    const soapBody=String(b.body || '');
    const refs=[...soapBody.matchAll(/<Reference\b[^>]*URI=["']([^"']*)["']/g)].map(m=>m[1]);
    const sigCount=(soapBody.match(/<(?:\w+:)?Signature\b/g)||[]).length;
    const infIds=[...soapBody.matchAll(/<[^>]*InfDeclaracaoPrestacaoServico\b[^>]*Id=["']([^"']+)["']/g)].map(m=>m[1]);
    const loteIds=[...soapBody.matchAll(/<[^>]*LoteRps\b[^>]*Id=["']([^"']+)["']/g)].map(m=>m[1]);
    console.log('GISS XML SIG DEBUG', JSON.stringify({sigCount,refs,infIds,loteIds}));
    const out=await mtlsRequest({
      url:String(b.url),
      method:String(b.method || 'POST'),
      headers:b.headers && typeof b.headers==='object' ? b.headers : {},
      body:soapBody,
      certChain:String(b.certChain),
      privateKey:String(b.privateKey)
    });
    return sendJson(res,200,out);
  }catch(e){
    return sendJson(res,502,{error:e instanceof Error?e.message:'Falha no proxy mTLS'});
  }
}

function serveStatic(req,res){
  let pathname;
  try{ pathname=decodeURIComponent(new URL(req.url,'http://localhost').pathname); }
  catch{ pathname='/'; }
  if(pathname.includes('..')){ res.writeHead(400); return res.end('Bad request'); }
  if(pathname.startsWith('/api/')){ res.writeHead(404,{'Content-Type':'application/json'}); return res.end('{"error":"Not found"}'); }

  const requested = pathname==='/' ? '/index.html' : pathname;
  const full = path.join(ROOT, requested);
  if(!full.startsWith(ROOT)){ res.writeHead(403); return res.end('Forbidden'); }

  fs.stat(full,(err,st)=>{
    if(!err && st.isFile()){
      const ext=path.extname(full).toLowerCase();
      res.writeHead(200,{'Content-Type':MIME[ext]||'application/octet-stream','Cache-Control':ext==='.html'?'no-cache':'public, max-age=3600'});
      fs.createReadStream(full).pipe(res);
      return;
    }
    // SPA fallback only for normal browser routes; suspicious dotfiles/known secret paths get 404.
    if(pathname.startsWith('/.') || /wp-config\.php|credentials|\.env/i.test(pathname)){
      res.writeHead(404,{'Content-Type':'text/plain; charset=utf-8'});
      return res.end('Not found');
    }
    const index=path.join(ROOT,'index.html');
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-cache'});
    fs.createReadStream(index).pipe(res);
  });
}

const server=http.createServer(async(req,res)=>{
  if(req.url && req.url.startsWith('/api/giss-proxy')) return handleProxy(req,res);
  return serveStatic(req,res);
});

server.listen(PORT,'0.0.0.0',()=>console.log('Seu BPO ouvindo na porta '+PORT));
