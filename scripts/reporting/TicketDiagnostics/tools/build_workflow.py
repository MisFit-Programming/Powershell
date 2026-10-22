"""Generate the reviewable n8n workflow. Standard nodes only; no community nodes."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
nodes, connections = [], {}

def node(name, kind, parameters, version=1):
    nodes.append(dict(id=name.lower().replace(' ', '-'), name=name,
                      type='n8n-nodes-base.' + kind, typeVersion=version,
                      position=[len(nodes) * 240, 0], parameters=parameters))
    return name

def connect(a, b, output=0):
    branches = connections.setdefault(a, {'main': []})['main']
    while len(branches) <= output:
        branches.append([])
    branches[output].append(dict(node=b, type='main', index=0))

def code(name, source):
    return node(name, 'code', {'jsCode': source}, 2)

def http(name, method, url, body=None, content='json', tolerant=False):
    p = dict(method=method, url='={{ ' + url + ' }}',
             authentication='genericCredentialType', genericAuthType='oAuth2Api',
             options={'timeout': 60000})
    if tolerant:
        p['options']['response'] = {'response': {'fullResponse': True, 'neverError': True, 'responseFormat': 'text', 'outputPropertyName': 'body'}}
    if body is not None:
        p['sendBody'] = True
        if content == 'binary':
            p.update(contentType='binaryData', inputDataFieldName='data',
                     sendHeaders=True, headerParameters={'parameters': [{'name': 'Content-Type', 'value': 'application/zip'}]})
        elif content == 'text':
            p.update(contentType='raw', rawContentType='text/plain; charset=utf-8', body='={{ ' + body + ' }}')
        else:
            p.update(specifyBody='json', jsonBody='={{ ' + body + ' }}')
    return node(name, 'httpRequest', p, 4.2)

def branch(name, expression):
    return node(name, 'if', {'conditions': {'options': {'caseSensitive': True, 'leftValue': '', 'typeValidation': 'strict', 'version': 2},
                    'conditions': [{'id': name, 'leftValue': '={{ '+expression+' }}', 'rightValue': '', 'operator': {'type': 'boolean', 'operation': 'true', 'singleValue': True}}], 'combinator': 'and'}, 'options': {}}, 2.2)

def response(name, value):
    return node(name, 'respondToWebhook', {'respondWith': 'json', 'responseBody': '={{ '+value+' }}', 'options': {}}, 1.4)

node('Authenticated intake', 'webhook', {'httpMethod': 'POST', 'path': 'crown-ticket-diagnostics-v1', 'authentication': 'headerAuth', 'responseMode': 'responseNode', 'options': {}}, 2)
nodes[-1]['webhookId'] = 'crown-ticket-diagnostics-v1'

code('Configuration and validation', r"""
// REQUIRED SETUP: select OAuth credentials on every Graph HTTP node and Header Auth on intake.
const config = {
  baseFolderId: 'REPLACE_WITH_PRIVATE_ONEDRIVE_FOLDER_ID',
  chatId: 'REPLACE_WITH_EXISTING_TEAMS_CHAT_ID',
  recipients: ['REPLACE_WITH_RECIPIENT_EMAIL'],
};
if (JSON.stringify(config).includes('REPLACE_WITH_')) throw new Error('Configure destination settings before enabling this workflow.');
if (!Array.isArray(config.recipients) || config.recipients.some(x => typeof x !== 'string' || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(x))) throw new Error('Recipients must be an array of email addresses; [] preserves existing access.');
const p = $input.first().json.body;
if (!p || typeof p !== 'object' || Array.isArray(p)) throw new Error('JSON object required.');
if (Buffer.byteLength(JSON.stringify(p), 'utf8') > 12*1024*1024) throw new Error('Payload exceeds 12 MiB.');
if (p.schemaVersion !== '1.0' || !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i.test(p.runId || '')) throw new Error('Invalid schema or run ID.');
for (const [key,max] of [['device',255],['ticketReference',120],['summary',12000],['markdown',12*1024*1024],['localPath',2000]]) {
  if (typeof p[key] !== 'string' || p[key].length > max) throw new Error('Invalid '+key);
}
if (!p.device || !['full','summary-only'].includes(p.deliveryMode)) throw new Error('Invalid delivery mode or device.');
if (typeof p.zipBase64 !== 'string' || !/^[a-f0-9]{64}$/i.test(p.zipSha256 || '')) throw new Error('Invalid ZIP metadata.');
if (p.deliveryMode === 'full') {
  if (!p.markdown || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(p.zipBase64)) throw new Error('Invalid bundle encoding.');
  const zip=Buffer.from(p.zipBase64,'base64');
  if (zip.length < 22 || zip.readUInt32LE(0) !== 0x04034b50) throw new Error('Invalid ZIP signature.');
  // Allow the built-in crypto module for Code nodes/task runners; see README.
  if (require('crypto').createHash('sha256').update(zip).digest('hex') !== p.zipSha256.toLowerCase()) throw new Error('ZIP checksum mismatch.');
} else if (p.zipBase64 || p.markdown) throw new Error('Summary-only payload must omit file contents.');
// Encode names deterministically and append a short hash to prevent sanitized-name collisions.
const segment = value => {
  const clean=value.replace(/[<>:"/\\|?*\x00-\x1f#%]/g,'_').replace(/^[. ]+|[. ]+$/g,'').slice(0,70) || 'Unnamed';
  return clean+'-'+require('crypto').createHash('sha256').update(value).digest('hex').slice(0,10);
};
return [{json:{...p,config, ticketFolder:segment(p.ticketReference || 'Unassigned'),deviceFolder:segment(p.device),graph:'https://graph.microsoft.com/v1.0/me/drive',reportText:p.deliveryMode==='full'?p.markdown:'# Summary only\n\n'+p.summary+'\n\nFull files remain on device: '+p.localPath}}];
""")
connect('Authenticated intake', 'Configuration and validation')
C = "$('Configuration and validation').first().json"

# Conflict=fail makes repeat folder creation deterministic. Only 201 and 409 are accepted;
# GET by exact path afterwards ensures a pre-existing file cannot masquerade as a folder.
previous = 'Configuration and validation'
parent = C+'.config.baseFolderId'
for label, field in [('Ticket', 'ticketFolder'), ('Device', 'deviceFolder'), ('Run', 'runId')]:
    create = http('Create '+label+' folder', 'POST', C+".graph+'/items/'+encodeURIComponent("+parent+")+ '/children'",
                  "{name:"+C+'.'+field+",folder:{},'@microsoft.graph.conflictBehavior':'fail'}", tolerant=True)
    check = code('Check '+label+' folder creation', "const r=$input.first().json;if (![201,409].includes(r.statusCode)) throw new Error('Folder creation failed: '+r.statusCode);return $input.all();")
    get = http('Get '+label+' folder', 'GET', C+".graph+'/items/'+encodeURIComponent("+parent+")+':/'+encodeURIComponent("+C+'.'+field+")")
    verify = code('Verify '+label+' folder', "const r=$input.first().json;if (!r.id || !r.folder) throw new Error('Expected folder');return $input.all();")
    connect(previous,create);connect(create,check);connect(check,get);connect(get,verify)
    previous=verify; parent="$('Get "+label+" folder').first().json.id"
R = "$('Get Run folder').first().json.id"
G = C+".graph+'/items/'+encodeURIComponent("+R+")"

http('Read delivery marker','GET', G+"+':/delivery.json:/content'",tolerant=True)
connect(previous,'Read delivery marker')
code('Inspect delivery marker', r"""
const r=$input.first().json;const p=$('Configuration and validation').first().json;
if (r.statusCode===404) return [{json:{complete:false}}];
if (r.statusCode!==200) throw new Error('Cannot read delivery state: '+r.statusCode);
const m=typeof r.body==='string'?JSON.parse(r.body):r.body;
if (m.runId!==p.runId || m.chatId!==p.config.chatId || m.zipSha256!==p.zipSha256 || !m.messageId || !['delivered','summary-delivered'].includes(m.status)) throw new Error('Invalid or conflicting stored delivery state; manual review required.');
return [{json:{complete:true,marker:m}}];
""")
connect('Read delivery marker','Inspect delivery marker')
branch('Already delivered', '$json.complete');connect('Inspect delivery marker','Already delivered')
http('Verify recorded Teams message','GET', "'https://graph.microsoft.com/v1.0/chats/'+encodeURIComponent("+C+".config.chatId)+'/messages/'+encodeURIComponent($('Inspect delivery marker').first().json.marker.messageId)")
connect('Already delivered','Verify recorded Teams message',0)
code('Confirm recorded delivery', "const m=$('Inspect delivery marker').first().json.marker;const r=$input.first().json;if(r.deletedDateTime || !r.body || !r.body.content.includes(m.runId)) throw new Error('Recorded Teams message is missing or changed; manual review required.');return [{json:m}];")
connect('Verify recorded Teams message','Confirm recorded delivery')
response('Return existing receipt','$json');connect('Confirm recorded delivery','Return existing receipt')

http('Acquire run lock','POST',G+"+'/children'", "{name:'delivery-lock',folder:{},'@microsoft.graph.conflictBehavior':'fail'}",tolerant=True)
connect('Already delivered','Acquire run lock',1)
code('Inspect run lock', "const r=$input.first().json;if(![201,409].includes(r.statusCode)) throw new Error('Cannot acquire delivery lock: '+r.statusCode);return [{json:{acquired:r.statusCode===201}}];")
connect('Acquire run lock','Inspect run lock')
branch('Lock acquired','$json.acquired');connect('Inspect run lock','Lock acquired')
response('Return pending receipt',"{runId:"+C+".runId,status:'pending-review',message:'Another execution owns this run, or an earlier attempt failed. Inspect n8n and Teams before releasing the OneDrive delivery-lock folder.'}")
connect('Lock acquired','Return pending receipt',1)

http('Upload report','PUT',G+"+':/Report.md:/content'",C+'.reportText','text')
connect('Lock acquired','Upload report',0)
branch('Full bundle',C+".deliveryMode === 'full'");connect('Upload report','Full bundle')
code('Prepare ZIP binary', "const p=$('Configuration and validation').first().json;return [{json:{runId:p.runId},binary:{data:await this.helpers.prepareBinaryData(Buffer.from(p.zipBase64,'base64'),'Bundle.zip','application/zip')}}];")
connect('Full bundle','Prepare ZIP binary',0)
http('Upload ZIP','PUT',G+"+':/Bundle.zip:/content'",'data','binary');connect('Prepare ZIP binary','Upload ZIP')
code('Full file links', "return [{json:{reportUrl:$('Upload report').first().json.webUrl,zipUrl:$input.first().json.webUrl}}];")
connect('Upload ZIP','Full file links')
code('Summary file link', "return [{json:{reportUrl:$('Upload report').first().json.webUrl,zipUrl:null}}];")
connect('Full bundle','Summary file link',1)
code('File links', r"const r=$input.first().json;for(const url of [r.reportUrl,r.zipUrl].filter(Boolean)){if(!/^https:\/\//i.test(url)) throw new Error('Missing secure file link.');}if(!r.reportUrl) throw new Error('Missing report link');return $input.all();")
connect('Full file links','File links');connect('Summary file link','File links')
http('Grant recipient read access','POST',G+"+'/invite'", "{recipients:"+C+".config.recipients.map(email=>({email})),requireSignIn:true,sendInvitation:false,roles:['read']}")
branch('Recipients configured',C+'.config.recipients.length > 0')
connect('File links','Recipients configured')
connect('Recipients configured','Grant recipient read access',0)
connect('Recipients configured','Check sharing and prepare message',1)
code('Check sharing and prepare message', r"""
const r=$input.first().json;
const p=$('Configuration and validation').first().json, links=$('File links').first().json;
if (p.config.recipients.length && (!Array.isArray(r.value) || r.value.length < new Set(p.config.recipients.map(x=>x.toLowerCase())).size || r.value.some(v=>v.error || !Array.isArray(v.roles) || !v.roles.includes('read')))) throw new Error('Recipient access could not be confirmed; no Teams message sent.');
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const html='<h3>Windows ticket diagnostics'+(p.deliveryMode==='summary-only'?' — SUMMARY ONLY':'')+'</h3>'+
 '<p><b>Device:</b> '+esc(p.device)+'<br><b>Ticket/project:</b> '+esc(p.ticketReference||'Unassigned')+'</p>'+
 '<p><b>Time-entry text / observations</b></p><p>'+esc(p.summary).replace(/\r?\n/g,'<br>')+'</p>'+
 '<p><a href="'+esc(links.reportUrl)+'">'+(p.deliveryMode==='full'?'Markdown report':'Summary (full files remain local)')+'</a>'+
 (links.zipUrl?' · <a href="'+esc(links.zipUrl)+'">Diagnostic ZIP</a>':'')+'</p>'+
 '<p>Run ID: '+esc(p.runId)+'</p>';
return [{json:{body:{contentType:'html',content:html}}}];
""")
connect('Grant recipient read access','Check sharing and prepare message')
http('Post Teams message','POST',"'https://graph.microsoft.com/v1.0/chats/'+encodeURIComponent("+C+".config.chatId)+'/messages'",'$json')
connect('Check sharing and prepare message','Post Teams message')
# Intentionally no retryOnFail on non-idempotent message creation.
code('Build delivery receipt', "const p=$('Configuration and validation').first().json;const m=$input.first().json;if(!m.id) throw new Error('No Teams message receipt');return [{json:{runId:p.runId,zipSha256:p.zipSha256,status:p.deliveryMode==='full'?'delivered':'summary-delivered',chatId:p.config.chatId,messageId:m.id,completedUtc:new Date().toISOString(),...$('File links').first().json}}];")
connect('Post Teams message','Build delivery receipt')
http('Persist delivery receipt','PUT',G+"+':/delivery.json:/content'","JSON.stringify($('Build delivery receipt').first().json)",'text')
connect('Build delivery receipt','Persist delivery receipt')
response('Return completed receipt',"$('Build delivery receipt').first().json")
connect('Persist delivery receipt','Return completed receipt')

workflow = dict(name='Crown - Windows Ticket Diagnostics',nodes=nodes,connections=connections,active=False,
                settings={'executionOrder':'v1','saveDataSuccessExecution':'none','saveDataErrorExecution':'none','saveManualExecutions':False,'executionTimeout':300},
                pinData={},tags=[])
(ROOT / 'TicketDiagnostics.n8n.json').write_text(json.dumps(workflow,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')
print(f'Generated {len(nodes)} nodes: {ROOT / "TicketDiagnostics.n8n.json"}')
