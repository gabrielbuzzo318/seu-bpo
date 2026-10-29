const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');
const { SignedXml } = require('xml-crypto');
const forge = require('node-forge');

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

function escapeXml(v){return String(v??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;')}

function gissResignSoap(soap, certChain, privateKey){
  const m=String(soap||'').match(/<nfseDadosMsg><!\[CDATA\[([\s\S]*?)\]\]><\/nfseDadosMsg>/);
  if(!m) return soap;
  let xml=m[1];
  if(!/EnviarLoteRps(?:Sincrono)?Envio/.test(xml)) return soap;

  xml=xml
    .replace(/<(?:ds:)?Signature\b[\s\S]*?<\/(?:ds:)?Signature>/g,'')
    
    .replace(/xmlns:g=/g,'xmlns:giss=')
    .replace(/<g:/g,'<giss:')
    .replace(/<\/g:/g,'</giss:')
    .replace(/Id="Dec_(\d+)"/g,'Id="RPS$1"')
    .replace(/Id="Lote_(\d+)"/g,'Id="LOTE$1"')
    .replace(/<tipos:CodigoPais>1058<\/tipos:CodigoPais>/g,'<tipos:CodigoPais>0076</tipos:CodigoPais>')
    .replace(/<tipos:ValorDeducoes>[^<]*<\/tipos:ValorDeducoes>/g,'')
    .replace(/<tipos:ValorPis>[^<]*<\/tipos:ValorPis>/g,'')
    .replace(/<tipos:ValorCofins>[^<]*<\/tipos:ValorCofins>/g,'')
    .replace(/<tipos:ValorInss>[^<]*<\/tipos:ValorInss>/g,'')
    .replace(/<tipos:ValorIr>[^<]*<\/tipos:ValorIr>/g,'')
    .replace(/<tipos:ValorCsll>[^<]*<\/tipos:ValorCsll>/g,'')
    .replace(/<tipos:OutrasRetencoes>[^<]*<\/tipos:OutrasRetencoes>/g,'')
    .replace(/<tipos:ValTotTributos>[^<]*<\/tipos:ValTotTributos>/g,'')
    .replace(/<tipos:ValorIss>[^<]*<\/tipos:ValorIss>/g,'')
    .replace(/<tipos:DescontoIncondicionado>[^<]*<\/tipos:DescontoIncondicionado>/g,'')
    .replace(/<tipos:DescontoCondicionado>[^<]*<\/tipos:DescontoCondicionado>/g,'');

  const addr=xml.match(/\[\[SBPADDR\|([^\]]+)\]\]/);
  if(addr){
    const parts=addr[1].split('|').map(v=>{try{return decodeURIComponent(v)}catch{return v}});
    const [endereco,numero,complemento,bairro,cidade,uf,cep]=parts;
    xml=xml.replace(/\s*\[\[SBPADDR\|[^\]]+\]\]/,'');
    const cidadeKey=String(cidade||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').trim().toUpperCase();
    const ufKey=String(uf||'SP').trim().toUpperCase();
    const ibge={
      'SAO JOSE DO RIO PRETO|SP':'3549805','SAO PAULO|SP':'3550308','LIMEIRA|SP':'3526902',
      'BRASILIA|DF':'5300108','TANABI|SP':'3553401','MIRASSOL|SP':'3530300','JOAO PESSOA|PB':'2507507',
      'UCHOA|SP':'3555604','CESARIO LANGE|SP':'3511607','CAMPINAS|SP':'3509502','ITAPAGIPE|MG':'3133402',
      'RIBEIRAO PRETO|SP':'3543402','BADY BASSITT|SP':'3504602','PORTO ALEGRE|RS':'4314902',
      'FRONTEIRA|MG':'3127008','CUIABA|MT':'5103403','VOTUPORANGA|SP':'3557105','COTIA|SP':'3513009',
      'CEDRAL|SP':'3511300','CURITIBA|PR':'4106902','TAIUVA|SP':'3553203','FRUTAL|MG':'3127107',
      'TORIXOREU|MT':'5108204','SAO CARLOS|SP':'3548906','SANTA FE DO SUL|SP':'3546603',
      'AMERICANA|SP':'3501608','JOSE BONIFACIO|SP':'3525706'
    };
    const cepKey=String(cep||'').replace(/\D/g,'');
    const ibgeCep={
      '13482376':'3526902','15170000':'3553401','73252200':'5300108','01311927':'3550308',
      '15135280':'3530300','71505790':'5300108','58037065':'2507507','15105000':'3540804',
      '15500006':'3557105','15894899':'3555604','15890310':'3555604','15135364':'3530300',
      '02357120':'3550308','38230000':'3127008','01510001':'3550308','14021617':'3543402',
      '15115000':'3504602','03607040':'3550308','15775000':'3546603','04533050':'3550308',
      '15500112':'3557105','18285901':'3511607','38400158':'3170206','13106001':'3509502',
      '78040600':'5103403','38240000':'3133402','06710140':'3513009',
      '15135854':'3530300','04505010':'3550308','15898004':'3511300','80240280':'4106902',
      '15135290':'3530300','14720000':'3553203','38200072':'3127107','13560320':'3548906',
      '02216030':'3550308','13468110':'3501608','15204094':'3525706'
    };
    const ufCep={
      '13482376':'SP','15170000':'SP','73252200':'DF','01311927':'SP',
      '15135280':'SP','71505790':'DF','58037065':'PB','15105000':'SP',
      '15500006':'SP','15894899':'SP','15890310':'SP','15135364':'SP',
      '02357120':'SP','38230000':'MG','01510001':'SP','14021617':'SP',
      '15115000':'SP','03607040':'SP','15775000':'SP','04533050':'SP',
      '15500112':'SP','18285901':'SP','38400158':'MG','13106001':'SP',
      '78040600':'MT','38240000':'MG','06710140':'SP',
      '15135854':'SP','04505010':'SP','15898004':'SP','80240280':'PR',
      '15135290':'SP','14720000':'SP','38200072':'MG','13560320':'SP',
      '02216030':'SP','13468110':'SP','15204094':'SP'
    };
    const codigoMunicipio=ibgeCep[cepKey]||ibge[cidadeKey+'|'+ufKey]||'3549805';
    const ufMunicipio=ufCep[cepKey]||ufKey;
    const bloco='<tipos:Endereco><tipos:Endereco>'+escapeXml(endereco||'')+'</tipos:Endereco><tipos:Numero>'+escapeXml(numero||'')+'</tipos:Numero>'
      +(complemento?'<tipos:Complemento>'+escapeXml(complemento)+'</tipos:Complemento>':'')
      +'<tipos:Bairro>'+escapeXml(bairro||'')+'</tipos:Bairro><tipos:CodigoMunicipio>'+codigoMunicipio+'</tipos:CodigoMunicipio><tipos:Uf>'+escapeXml(ufMunicipio)+'</tipos:Uf><tipos:Cep>'+String(cep||'').replace(/\D/g,'')+'</tipos:Cep></tipos:Endereco>';
    xml=xml.replace(/(<\/tipos:RazaoSocial>)(?![\s\S]*?<tipos:Endereco>)/,'$1'+bloco);
  }

  if(!xml.includes('<tipos:trib>')){
    xml=xml.replace(/(<tipos:Aliquota>[^<]+<\/tipos:Aliquota>)/,
      '$1<tipos:trib><tipos:totTrib><tipos:pTotTribSN>0.00</tipos:pTotTribSN></tipos:totTrib></tipos:trib><tipos:IBSCBS><tipos:finNFSe>0</tipos:finNFSe><tipos:indFinal>0</tipos:indFinal><tipos:cIndOp>020301</tipos:cIndOp><tipos:tpOper>1</tipos:tpOper><tipos:tpEnteGov>4</tipos:tpEnteGov><tipos:indDest>0</tipos:indDest><tipos:valores><tipos:trib><tipos:gIBSCBS><tipos:CST>200</tipos:CST><tipos:cClassTrib>200046</tipos:cClassTrib></tipos:gIBSCBS></tipos:trib><tipos:cLocalidadeIncid>3549805</tipos:cLocalidadeIncid><tipos:pRedutor>0.00</tipos:pRedutor></tipos:valores></tipos:IBSCBS>');
  }

  const leaf=String(certChain||'').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0]||String(certChain||'');
  const certBase64=leaf.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g,'');
  const c14n='http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  const rsa='http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  const sha1='http://www.w3.org/2000/09/xmldsig#sha1';
  const env='http://www.giss.com.br/enviar-lote-rps-envio-v2_04.xsd';
  const tipos='http://www.giss.com.br/tipos-v2_04.xsd';
  const ds='http://www.w3.org/2000/09/xmldsig#';

  const signOne=(input,id)=>{
    const sig=new SignedXml({
      privateKey:String(privateKey),
      publicCert:leaf,
      signatureAlgorithm:rsa,
      canonicalizationAlgorithm:c14n,
      getKeyInfoContent:()=>'<ds:X509Data><ds:X509Certificate>'+certBase64+'</ds:X509Certificate></ds:X509Data>'
    });
    sig.addReference({
      xpath:"//*[@Id='"+id+"']",
      transforms:['http://www.w3.org/2000/09/xmldsig#enveloped-signature',c14n],
      digestAlgorithm:sha1
    });
    sig.computeSignature(input,{
      prefix:'ds',
      location:{reference:"//*[@Id='"+id+"']",action:'after'},
      existingPrefixes:{giss:env,tipos,ds}
    });
    return sig.getSignedXml();
  };

  const rpsIds=[...xml.matchAll(/<tipos:InfDeclaracaoPrestacaoServico\b[^>]*Id="([^"]+)"/g)].map(x=>x[1]);
  const loteId=xml.match(/<giss:LoteRps\b[^>]*Id="([^"]+)"/)?.[1]||'';
  if(rpsIds.length===1) xml=signOne(xml,rpsIds[0]);
  if(loteId) xml=signOne(xml,loteId);

  console.log('GISS RESIGN',JSON.stringify({rpsIds,loteId,sigCount:(xml.match(/<ds:Signature\b/g)||[]).length}));
  return String(soap).replace(m[1],xml);
}

function gissSignConsultaSoap(soap, certChain, privateKey){
  const m=String(soap||'').match(/<nfseDadosMsg><!\[CDATA\[([\s\S]*?)\]\]><\/nfseDadosMsg>/);
  if(!m) return soap;
  let xml=m[1];
  if(!/ConsultarLoteRpsEnvio/.test(xml) || /<(?:ds:)?Signature\b/.test(xml)) return soap;

  const leaf=String(certChain||'').match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/)?.[0]||String(certChain||'');
  const certBase64=leaf.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s+/g,'');
  const c14n='http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
  const rsa='http://www.w3.org/2000/09/xmldsig#rsa-sha1';
  const sha1='http://www.w3.org/2000/09/xmldsig#sha1';

  const sig=new SignedXml({
    privateKey:String(privateKey),
    publicCert:leaf,
    signatureAlgorithm:rsa,
    canonicalizationAlgorithm:c14n,
    getKeyInfoContent:()=>'<ds:X509Data><ds:X509Certificate>'+certBase64+'</ds:X509Certificate></ds:X509Data>'
  });
  sig.addReference({
    xpath:'/*',
    transforms:['http://www.w3.org/2000/09/xmldsig#enveloped-signature',c14n],
    digestAlgorithm:sha1,
    isEmptyUri:true
  });
  sig.computeSignature(xml,{
    prefix:'ds',
    location:{reference:'/*',action:'append'},
    existingPrefixes:{ds:'http://www.w3.org/2000/09/xmldsig#'}
  });
  xml=sig.getSignedXml();
  console.log('GISS CONSULTA SIGN',JSON.stringify({sigCount:(xml.match(/<ds:Signature\b/g)||[]).length}));
  return String(soap).replace(m[1],xml);
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
    let soapBody=String(b.body || '');
    soapBody=gissResignSoap(soapBody,String(b.certChain||''),String(b.privateKey||''));
    soapBody=gissSignConsultaSoap(soapBody,String(b.certChain||''),String(b.privateKey||''));
    const refs=[...soapBody.matchAll(/<(?:\w+:)?Reference\b[^>]*URI=["']([^"']*)["']/g)].map(m=>m[1]);
    const sigCount=(soapBody.match(/<(?:\w+:)?Signature\b/g)||[]).length;
    const infIds=[...soapBody.matchAll(/<[^>]*InfDeclaracaoPrestacaoServico\b[^>]*Id=["']([^"']+)["']/g)].map(m=>m[1]);
    const loteIds=[...soapBody.matchAll(/<[^>]*LoteRps\b[^>]*Id=["']([^"']+)["']/g)].map(m=>m[1]);
    console.log('GISS XML SIG DEBUG', JSON.stringify({sigCount,refs,infIds,loteIds}));
    const out=await mtlsRequest({
      url:String(b.url),
      method:String(b.method || 'POST'),
      headers:{
        ...(b.headers && typeof b.headers==='object' ? b.headers : {}),
        ...(soapBody.includes('RecepcionarLoteRpsRequest')?{'SOAPAction':'"http://nfse.abrasf.org.br/RecepcionarLoteRps"'}:{}),
        ...(soapBody.includes('ConsultarLoteRpsRequest')?{'SOAPAction':'"http://nfse.abrasf.org.br/ConsultarLoteRps"'}:{})
      },
      body:soapBody,
      certChain:String(b.certChain),
      privateKey:String(b.privateKey)
    });
    return sendJson(res,200,out);
  }catch(e){
    return sendJson(res,502,{error:e instanceof Error?e.message:'Falha no proxy mTLS'});
  }
}


const SUPABASE_URL='https://fkdlpdwpaadgkeouzobt.supabase.co';
const SUPABASE_ANON='sb_publishable_QmY54I85Yo_cPFSvONXz1g__HO70qKh';

function xmlTagText(xml,name){
  const m=String(xml||'').match(new RegExp('<(?:\\w+:)?'+name+'\\b[^>]*>([\\s\\S]*?)<\\/(?:\\w+:)?'+name+'>','i'));
  return (m?.[1]||'').trim();
}
function xmlDecodeText(v){
  return String(v||'').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&quot;/g,'"').replace(/&apos;/g,"'").replace(/&amp;/g,'&');
}
function parsePfxBytes(buf,password){
  const bin=Buffer.from(buf).toString('binary');
  const p12=forge.pkcs12.pkcs12FromAsn1(forge.asn1.fromDer(bin),false,password);
  const kb=p12.getBags({bagType:forge.pki.oids.pkcs8ShroudedKeyBag})[forge.pki.oids.pkcs8ShroudedKeyBag]
    ||p12.getBags({bagType:forge.pki.oids.keyBag})[forge.pki.oids.keyBag]||[];
  const cb=p12.getBags({bagType:forge.pki.oids.certBag})[forge.pki.oids.certBag]||[];
  if(!kb[0]?.key||!cb.length) throw new Error('Certificado A1 inválido.');
  const certs=cb.filter(x=>x.cert).map(x=>forge.pki.certificateToPem(x.cert));
  return {privateKey:forge.pki.privateKeyToPem(kb[0].key),certChain:certs.join('\n')};
}
async function supaFetch(pathname,token,opts={}){
  const headers={
    apikey:SUPABASE_ANON,
    Authorization:'Bearer '+token,
    ...(opts.headers||{})
  };
  return fetch(SUPABASE_URL+pathname,{...opts,headers});
}
function cdataWrap(v){return '<![CDATA['+String(v).replace(/]]>/g,']]]]><![CDATA[>')+']]>';}

async function handleGissConsultar(req,res){
  if(req.method!=='POST') return sendJson(res,405,{error:'Método inválido'});
  try{
    const auth=String(req.headers.authorization||'');
    const token=auth.replace(/^Bearer\s+/i,'');
    if(!token) return sendJson(res,401,{error:'Sessão inválida'});
    const b=JSON.parse(await readBody(req)||'{}');
    const empresaId=String(b.empresa_id||'');
    const requestId=String(b.request_id||'');
    const password=String(b.password||'');
    if(!empresaId||!requestId||!password) return sendJson(res,400,{error:'Dados incompletos para consultar a GISS.'});

    const qs=(table,filter,select)=>'/rest/v1/'+table+'?'+filter+'&select='+encodeURIComponent(select);
    const er=await supaFetch(qs('seubpo_nfse_emissoes','empresa_id=eq.'+encodeURIComponent(empresaId)+'&request_id=eq.'+encodeURIComponent(requestId),'request_id,status,protocolo,rps_numero'),token);
    if(!er.ok) throw new Error('Não foi possível ler a emissão.');
    const emiss=(await er.json())[0];
    if(!emiss?.protocolo) return sendJson(res,400,{error:'Essa emissão ainda não possui protocolo da GISS.'});

    const cr=await supaFetch(qs('seubpo_nfse_config','empresa_id=eq.'+encodeURIComponent(empresaId),'cnpj,inscricao_municipal,ambiente,endpoint_producao,endpoint_homologacao'),token);
    if(!cr.ok) throw new Error('Não foi possível ler a configuração da GISS.');
    const cfg=(await cr.json())[0];
    if(!cfg) throw new Error('Configuração da GISS não encontrada.');

    const certMetaR=await supaFetch(qs('seubpo_certificados','empresa_id=eq.'+encodeURIComponent(empresaId),'storage_path'),token);
    if(!certMetaR.ok) throw new Error('Não foi possível localizar o certificado.');
    const certMeta=(await certMetaR.json())[0];
    if(!certMeta?.storage_path) throw new Error('Certificado A1 não cadastrado.');

    const objectPath=String(certMeta.storage_path).split('/').map(encodeURIComponent).join('/');
    const certR=await supaFetch('/storage/v1/object/authenticated/seubpo-certificados/'+objectPath,token);
    if(!certR.ok) throw new Error('Não foi possível ler o certificado A1.');
    let cert;
    try{cert=parsePfxBytes(await certR.arrayBuffer(),password)}
    catch{ return sendJson(res,400,{error:'Senha do certificado incorreta ou A1 inválido.'}); }

    const tipos='http://www.giss.com.br/tipos-v2_04.xsd';
    const consultaNs='http://www.giss.com.br/consultar-lote-rps-envio-v2_04.xsd';
    const cabNs='http://www.giss.com.br/cabecalho-v2_04.xsd';
    const soapNs='http://schemas.xmlsoap.org/soap/envelope/';
    const svc='http://nfse.abrasf.org.br';
    const data='<q:ConsultarLoteRpsEnvio xmlns:q="'+consultaNs+'" xmlns:tipos="'+tipos+'"><q:Prestador><tipos:CpfCnpj><tipos:Cnpj>'+String(cfg.cnpj||'').replace(/\D/g,'')+'</tipos:Cnpj></tipos:CpfCnpj><tipos:InscricaoMunicipal>'+escapeXml(cfg.inscricao_municipal||'')+'</tipos:InscricaoMunicipal></q:Prestador><q:Protocolo>'+escapeXml(emiss.protocolo)+'</q:Protocolo></q:ConsultarLoteRpsEnvio>';
    const header='<cabecalho xmlns="'+cabNs+'" versao="2.04"><versaoDados>2.04</versaoDados></cabecalho>';
    let soap='<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="'+soapNs+'" xmlns:nfse="'+svc+'"><soapenv:Header/><soapenv:Body><nfse:ConsultarLoteRpsRequest><nfseCabecMsg>'+cdataWrap(header)+'</nfseCabecMsg><nfseDadosMsg>'+cdataWrap(data)+'</nfseDadosMsg></nfse:ConsultarLoteRpsRequest></soapenv:Body></soapenv:Envelope>';
    soap=gissSignConsultaSoap(soap,cert.certChain,cert.privateKey);

    const endpoint=String(cfg.ambiente==='homologacao'?cfg.endpoint_homologacao:cfg.endpoint_producao).replace(/\?wsdl.*$/i,'');
    const out=await mtlsRequest({
      url:endpoint,
      method:'POST',
      headers:{'Content-Type':'text/xml; charset=utf-8','SOAPAction':'"http://nfse.abrasf.org.br/ConsultarLoteRps"'},
      body:soap,
      certChain:cert.certChain,
      privateKey:cert.privateKey
    });
    if(out.status<200||out.status>=300) throw new Error('GISS HTTP '+out.status);

    const inner=xmlDecodeText(xmlTagText(out.body,'outputXML')||xmlTagText(out.body,'return')||out.body);
    const situacao=xmlTagText(inner,'Situacao');
    const comp=[...inner.matchAll(/<(?:\w+:)?CompNfse\b[^>]*>([\s\S]*?)<\/(?:\w+:)?CompNfse>/gi)];
    let nota=null;
    for(const m of comp){
      const bloco=m[1];
      const ident=bloco.match(/<(?:\w+:)?IdentificacaoRps\b[^>]*>([\s\S]*?)<\/(?:\w+:)?IdentificacaoRps>/i)?.[1]||'';
      const rps=Number(xmlTagText(ident,'Numero')||0);
      if(!nota||rps===Number(emiss.rps_numero)){
        nota={rps,numero_nfse:xmlTagText(bloco,'Numero'),codigo_verificacao:xmlTagText(bloco,'CodigoVerificacao')};
        if(rps===Number(emiss.rps_numero)) break;
      }
    }
    const msg=xmlTagText(inner,'Mensagem');
    const cod=xmlTagText(inner,'Codigo');

    let patch;
    let result;
    if(nota?.numero_nfse){
      patch={status:'EMITIDA',numero_nfse:nota.numero_nfse,codigo_verificacao:nota.codigo_verificacao||null,xml_retorno:inner,erro_codigo:null,erro_mensagem:null,atualizado_em:new Date().toISOString()};
      result={ok:true,situacao,protocolo:emiss.protocolo,rps:emiss.rps_numero,numero_nfse:nota.numero_nfse,codigo_verificacao:nota.codigo_verificacao||''};
    }else if(situacao==='2'){
      patch={status:'PROCESSANDO',xml_retorno:inner,erro_codigo:null,erro_mensagem:'Remessa ainda não foi processada',atualizado_em:new Date().toISOString()};
      result={ok:false,processando:true,situacao,protocolo:emiss.protocolo,rps:emiss.rps_numero,erro:'Remessa ainda não foi processada'};
    }else{
      patch={status:'ERRO',xml_retorno:inner,erro_codigo:cod||null,erro_mensagem:msg||('Situação '+situacao),atualizado_em:new Date().toISOString()};
      result={ok:false,situacao,protocolo:emiss.protocolo,rps:emiss.rps_numero,codigo:cod||'',erro:msg||('Situação '+situacao)};
    }

    const up=await supaFetch('/rest/v1/seubpo_nfse_emissoes?empresa_id=eq.'+encodeURIComponent(empresaId)+'&request_id=eq.'+encodeURIComponent(requestId),token,{
      method:'PATCH',
      headers:{'Content-Type':'application/json','Prefer':'return=minimal'},
      body:JSON.stringify(patch)
    });
    if(!up.ok) console.warn('Falha ao persistir consulta GISS',up.status);

    return sendJson(res,200,result);
  }catch(e){
    return sendJson(res,502,{error:e instanceof Error?e.message:'Falha ao consultar a GISS.'});
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
  if(req.url && req.url.startsWith('/api/giss-consultar')) return handleGissConsultar(req,res);
  return serveStatic(req,res);
});

server.listen(PORT,'0.0.0.0',()=>console.log('Seu BPO ouvindo na porta '+PORT));
