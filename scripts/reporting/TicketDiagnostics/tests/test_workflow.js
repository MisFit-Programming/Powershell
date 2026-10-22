// Execute the exported workflow's actual Code nodes, expressions and branches
// against a deterministic Graph mock. This does not claim live n8n compatibility.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert/strict');
const workflow = JSON.parse(fs.readFileSync(path.join(__dirname,'..','TicketDiagnostics.n8n.json'),'utf8'));
const byName = new Map(workflow.nodes.map(n=>[n.name,n]));
let checks=0;
function check(value,message){assert.ok(value,message);checks++;}
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
for(const node of workflow.nodes){
  if(node.type.endsWith('.code')) new AsyncFunction('$input','$','require','Buffer',node.parameters.jsCode);
  check(!node.retryOnFail,'No non-idempotent automatic retries');
}
for(const [name,edges] of Object.entries(workflow.connections)) {
  check(byName.has(name),'Connection source exists');
  for(const branch of edges.main) for(const edge of branch) check(byName.has(edge.node),'Connection destination exists');
}
check(byName.get('Authenticated intake').parameters.authentication==='headerAuth','Header authentication required');
check(!workflow.active,'Import is inactive');

class GraphMock {
  constructor(){this.folders=new Map([['base',{id:'base',folder:{}}]]);this.child=new Map();this.files=new Map();this.messages=new Map();this.count=0;this.failAt=null;this.failOnce=true;this.partialShare=false;}
  async request(node,url,body,item){
    if(this.failAt===node.name){if(this.failOnce)this.failAt=null;throw Error('Injected failure: '+node.name);}
    const method=node.parameters.method;
    let status=200,result;
    const prefix='https://graph.microsoft.com/v1.0/me/drive/items/';
    if(url.startsWith(prefix)){
      const rest=url.slice(prefix.length);
      if(rest.endsWith('/children')){
        const parent=decodeURIComponent(rest.slice(0,-9)),key=parent+'/'+body.name;
        if(this.child.has(key)){status=409;result={error:{code:'nameAlreadyExists'}};}
        else {status=201;result={id:'folder-'+(++this.count),folder:{},name:body.name};this.child.set(key,result);this.folders.set(result.id,result);}
      } else if(rest.endsWith('/invite')){
        result={value:body.recipients.map(x=>({roles:['read'],grantedToV2:{user:{email:x.email}}}))};
        if(this.partialShare) result.value=[{error:{code:'accessDenied'}}];
      } else {
        const match=rest.match(/^([^:]+):\/([^:]+)(:\/content)?$/);
        assert.ok(match,'Expected supported Graph URL: '+url);
        const parent=decodeURIComponent(match[1]),name=decodeURIComponent(match[2]),key=parent+'/'+name;
        if(match[3]){
          if(method==='PUT'){
            const data=node.parameters.contentType==='binaryData'?item.binary.data.bytes:body;
            this.files.set(key,data);status=201;result={id:'file-'+key,webUrl:'https://tenant.example/'+encodeURIComponent(key)};
          } else if(this.files.has(key))result=this.files.get(key);
          else {status=404;result={error:{code:'itemNotFound'}};}
        } else {
          result=this.child.get(key);if(!result){status=404;result={error:{code:'itemNotFound'}};}
        }
      }
    } else if(url.startsWith('https://graph.microsoft.com/v1.0/chats/')){
      if(method==='POST'){result={id:'message-'+(++this.count),...body};this.messages.set(result.id,result);status=201;}
      else {const id=decodeURIComponent(url.split('/').pop());result=this.messages.get(id);if(!result){status=404;result={error:{code:'notFound'}};}}
    } else throw Error('Unexpected external URL: '+url);
    if(node.parameters.options.response){
      const field=node.parameters.options.response.response.outputPropertyName || 'data';
      return {statusCode:status,[field]:typeof result==='string'?result:JSON.stringify(result)};
    }
    if(status>=400)throw Error('Graph '+status);
    return result;
  }
}

async function execute(payload,graph,noRecipients=false){
  let name='Configuration and validation',items=[{json:{body:payload}}],hops=0;
  const outputs=new Map();
  const $=n=>({first:()=>{if(!outputs.has(n))throw Error('Unexecuted node '+n);return outputs.get(n)[0];}});
  while(name){
    if(++hops>80)throw Error('Unexpected loop');
    const n=byName.get(name),input=items;let branch=0;
    const evaluate=s=>typeof s==='string'&&s.startsWith('={{ ')?new Function('$','$json', 'return ('+s.slice(4,-3)+');')($,input[0].json):s;
    if(n.type.endsWith('.code')){
      const code=n.parameters.jsCode.replace('REPLACE_WITH_PRIVATE_ONEDRIVE_FOLDER_ID','base').replace('REPLACE_WITH_EXISTING_TEAMS_CHAT_ID','chat-1').replace("['REPLACE_WITH_RECIPIENT_EMAIL']",noRecipients?'[]':"['tech@example.com']");
      items=await new AsyncFunction('$input','$','require','Buffer',code).call({helpers:{prepareBinaryData:async(bytes,fileName,mimeType)=>({bytes,fileName,mimeType})}},{first:()=>input[0],all:()=>input},$,require,Buffer);
    } else if(n.type.endsWith('.if')){
      branch=evaluate(n.parameters.conditions.conditions[0].leftValue)?0:1;
    } else if(n.type.endsWith('.httpRequest')){
      const p=n.parameters;
      const body=p.specifyBody==='json'?evaluate(p.jsonBody):p.contentType==='raw'?evaluate(p.body):null;
      items=[{json:await graph.request(n,evaluate(p.url),body,input[0])}];
    } else if(n.type.endsWith('.respondToWebhook'))return evaluate(n.parameters.responseBody);
    else throw Error('Unsupported test node '+n.type);
    outputs.set(name,items);
    name=workflow.connections[name]?.main[branch]?.[0]?.node;
  }
  throw Error('Workflow did not respond');
}

async function main(){
  // Minimal signature-bearing bytes: intake validates signature/hash, never extracts untrusted ZIPs.
  const bytes=Buffer.alloc(30);bytes.writeUInt32LE(0x04034b50,0);
  const payload={schemaVersion:'1.0',runId:'11111111-1111-4111-8111-111111111111',device:'PC-1',ticketReference:'T-1',summary:'Collected <script>x</script> & café.',markdown:'# Evidence\nUnicode: café',localPath:'C:\\Diagnostics',deliveryMode:'full',zipBase64:bytes.toString('base64'),zipSha256:crypto.createHash('sha256').update(bytes).digest('hex').toUpperCase()};
  const graph=new GraphMock();const result=await execute(payload,graph);
  check(result.status==='delivered','Full delivery completes');
  check(graph.messages.size===1,'Single Teams message');
  check([...graph.messages.values()][0].body.content.includes('&lt;script&gt;'),'Teams escapes evidence');
  check([...graph.files.keys()].some(k=>k.endsWith('/Bundle.zip')),'ZIP uploaded');
  check([...graph.files.keys()].some(k=>k.endsWith('/Report.md')),'Markdown uploaded');
  const again=await execute(payload,graph);
  check(again.messageId===result.messageId&&graph.messages.size===1,'Retry verifies recorded message without reposting');
  await assert.rejects(()=>execute({...payload,zipSha256:'A'.repeat(64)},graph),/checksum mismatch/);checks++;
  await assert.rejects(()=>execute({...payload,device:'x'.repeat(256)},new GraphMock()),/Invalid device/);checks++;
  await assert.rejects(()=>execute({...payload,markdown:'x'.repeat(13*1024*1024)},new GraphMock()),/12 MiB/);checks++;
  const summaryGraph=new GraphMock();const summary=await execute({...payload,deliveryMode:'summary-only',zipBase64:'',markdown:''},summaryGraph);
  check(summary.status==='summary-delivered','Summary-only receipt');
  check(![...summaryGraph.files.keys()].some(k=>k.endsWith('/Bundle.zip')),'Summary-only does not claim ZIP upload');
  const privateGraph=new GraphMock();privateGraph.failAt='Grant recipient read access';
  const privateResult=await execute(payload,privateGraph,true);
  check(privateResult.status==='delivered','Empty recipients supports delivery');
  check(privateGraph.failAt==='Grant recipient read access','Empty recipients skips permission changes');
  for(const failAt of ['Upload report','Upload ZIP','Grant recipient read access','Post Teams message','Persist delivery receipt']){
    const mock=new GraphMock();mock.failAt=failAt;
    await assert.rejects(()=>execute(payload,mock),/Injected failure/);checks++;
    const count=mock.messages.size;
    const retry=await execute(payload,mock);
    check(retry.status==='pending-review','Failure lock requires review: '+failAt);
    check(mock.messages.size===count,'Retry never duplicates ambiguous message: '+failAt);
  }
  const share=new GraphMock();share.partialShare=true;
  await assert.rejects(()=>execute(payload,share),/Recipient access/);checks++;
  check(share.messages.size===0,'Partial sharing failure prevents Teams links');
  graph.messages.clear();await assert.rejects(()=>execute(payload,graph),/Graph 404/);checks++;
  console.log(`PASS: ${checks} workflow assertions. Graph and n8n are mocked; live import/OAuth checks remain required.`);
}
main().catch(e=>{console.error(e);process.exitCode=1;});
