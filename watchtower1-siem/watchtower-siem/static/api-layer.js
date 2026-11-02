/* Switches the UI from simulated data to the live backend API. */
(function(){
let last=0,busy=false;
async function A(m,p,b){const h={'Content-Type':'application/json'},k=sessionStorage.getItem('k');if(k)h['X-API-Key']=k;
 const r=await fetch('/api'+p,{method:m,headers:h,body:b?JSON.stringify(b):undefined});
 if(r.status===401){const k2=prompt('API key');if(k2){sessionStorage.setItem('k',k2);return A(m,p,b)}throw new Error('auth')}
 if(!r.ok)throw new Error(await r.text());return r.json()}
async function poll(){if(busy)return;busy=true;try{const s=await A('GET','/state?after='+last);if(S.v==='tq')S.tq=await A('GET','/triage');if(S.v==='mx')S.mx=await A('GET','/eval');
 if(s.events.length){ev=s.events.concat(ev).slice(0,3000);last=Math.max(last,...s.events.map(e=>+e.id.slice(1)))}
 inc=s.incidents;rules=s.rules;iocs=s.iocs;plog=s.plog;audit=s.audit;S.total=s.total;S.sources=s.sources;rNav();
 const f=document.activeElement&&/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName),open=$('#modal').style.display==='flex';
 if(S.v==='ov'||(!f&&!open&&['inc','ru','ti','pb','ad','co','tq','mx'].includes(S.v)))rMain()}catch(e){}busy=false}
async function act(m,p,b,msg){try{const r=await A(m,p,b);if(msg)toast(msg);await poll();rMain();return r}catch(e){toast('Error: '+e.message)}}
// disable the in-browser simulator and client-side detection
mk=()=>null;evalRules=()=>{};ev=[];inc=[];audit=[];plog=[];
simulate=()=>act('POST','/simulate',null,'Simulated intrusion sent through the ingest pipeline');
setInc=(id,f,v)=>act('PATCH','/incidents/'+id,{field:f,value:v},id+': '+f+' is now '+v);
addNote=async id=>{const v=$('#nt').value.trim();if(!v)return toast('Write a note first');await act('POST','/incidents/'+id+'/notes',{text:v})};
runPb=async(id,k)=>{if(!id)return toast('Select an open incident first');const r=await act('POST','/incidents/'+id+'/playbook',{k});if(r)toast(pbs[k].n+': '+r.result)};
addRule=()=>{const n=$('#rn').value.trim(),q=$('#rq').value.trim();if(!n||!q)return toast('Name and query are required');act('POST','/rules',{name:n,q,thr:+$('#rt').value||1,sev:$('#rs').value,mitre:$('#rm').value||'n/a'},'Rule added')};
tog=id=>act('POST','/rules/'+id+'/toggle');delRule=id=>act('DELETE','/rules/'+id,null,'Rule deleted');
runRule=async id=>{const r=await act('POST','/rules/'+id+'/run');if(r)toast(r.created+' new incident(s)')};
addIoc=()=>{const v=$('#iv').value.trim();if(!v)return toast('Enter an indicator');act('POST','/iocs',{v,t:$('#it').value,s:$('#is').value||'Manual'},'Indicator added')};
delIoc=i=>act('DELETE','/iocs/'+iocs[i].id,null,'Indicator removed');
scanIoc=async()=>{const r=await act('POST','/iocs/scan');if(r)toast(r.created?r.created+' incident(s) opened from IOC matches':'No new matches')};
evInc=async id=>{const r=await act('POST','/events/'+id+'/incident');if(r){mc();S.si=r.id;go('inc')}};
evIoc=async id=>{const e=ev.find(x=>x.id===id);await act('POST','/iocs',{v:e.ip,t:'IP',s:'Analyst'},e.ip+' added to threat intel');mc()};
runQ=async()=>{const qe=$('#q');if(qe)S.q=qe.value;const te=$('#tr');if(te)S.tr=+te.value;let r;
 try{r=await A('POST','/search',{q:S.q,hours:S.tr})}catch(e){return $('#res').innerHTML='<div class="m">Search failed: '+esc(e.message)+'</div>'}
 if(r.agg){S.res=[];$('#res').innerHTML=table(['value','count'],r.agg.map(([k,v])=>[esc(k||'n/a'),v]))}
 else{S.res=r.rows;$('#res').innerHTML=`<div class="m">${r.total} events matched, showing up to 100 (searched on the server)</div>`+table(['Time','Source','Event','Sev','Host','User','IP'],r.rows.map(e=>[fmt(e.t),e.source,esc(e.event),tag(e.sev),e.host,e.user,`<span class="mono">${e.ip}</span>`]),'showEv',r.rows.map(e=>e.id))}};
const vti=V.ti;V.ti=()=>vti().replace(/iocs\.splice\((\d+),1\);log\('IOC removed'\);render\(\)/g,'delIoc($1)');
V.co=()=>`<div class="card"><b>Ingestion endpoints</b><p class="m">Syslog (RFC 3164) over UDP port 5514. HTTP: POST JSON, a JSON array, NDJSON, or raw syslog lines to <span class="mono">/api/ingest</span>.</p></div><div class="grid">${(S.sources||[]).map(s=>`<div class="card"><b>${esc(s.source)}</b><div class="k">${s.c}</div><div class="m">events in the last hour</div></div>`).join('')||'<div class="m">No events received yet.</div>'}</div>`;

// ---- Wazuh triage console ----
NAV.splice(2,0,['tq','Triage queue'],['mx','Evaluation']);
const g0=go;go=v=>{g0(v);poll()};
const VD={true_positive:'high',false_positive:'info',escalate:'medium'},nm=v=>String(v||'').replace('_',' ');
V.tq=()=>{const l=S.tq||[];return`<div class="card"><div class="m">${l.length} Wazuh alerts. The triage service (tools/triage_stub.py or your LLM agent) posts reports; analysts approve or reject them here. Click a row to open it.</div>${table(['Time','Agent','Alert','Wazuh level','Baseline','AI verdict','MITRE','Status','Labels'],l.map(a=>[fmt(a.t),esc(a.host),esc(a.event),a.meta.level,nm(a.baseline),a.verdict?`<span class="tag ${VD[a.verdict]}">${nm(a.verdict)}</span>`:'<span class="m">no report</span>',esc(a.tech||''),a.decision||(a.rid?'awaiting decision':''),esc(a.labs||'')]),'openTri',l.map(a=>a.id.slice(1)))}</div>`};
V.mx=()=>{const m=S.mx;if(!m)return'<div class="m">Loading...</div>';const c=(k,v,u)=>`<div class="card"><div class="k">${v==null?'n/a':v+(u||'')}</div><div class="m">${k}</div></div>`;
return`<div class="grid">${c('AI accuracy',m.accuracy_pct,'%')}${c('Wazuh-level baseline accuracy',m.baseline_level_accuracy_pct,'%')}${c('Malicious recall (strict)',m.malicious_recall_pct,'%')}${c('Malicious recall incl. escalate',m.malicious_recall_incl_escalate_pct,'%')}${c('Reports passing validator',m.valid_reports_pct,'%')}${c('Median latency',m.median_latency_ms,' ms')}${c('Total LLM cost',m.total_cost_usd,' USD')}${c('Labeler agreement (Cohen kappa)',m.labeler_kappa)}</div><div class="card m">${m.labelled} labelled alerts (${m.disputed} disputed, label as "adjudicated" to resolve), ${m.reports} reports, ${m.evaluated} evaluated, ${m.approved} approved and ${m.rejected} rejected by analysts. Accuracy is computed only on alerts that have both a label and a report. Strict recall counts only a true positive verdict.</div>`};
const ev2=a=>(a.evidence||[]).map(x=>typeof x==='string'?{id:x,text:''}:x);
window.openTri=async id=>{let d;try{d=await A('GET','/triage/'+id)}catch(e){return toast('Error: '+e.message)}const r=d.report,e=d.event;
 modal(`<b>${esc(e.event)}</b><div class="m">${fmt(e.t)} on ${esc(e.host)}. User ${esc(e.user||'n/a')}, IP ${esc(e.ip||'n/a')}</div><div class="row">${tag(e.sev)} Wazuh level ${d.meta.level}, rule ${esc(d.meta.rule_id||'')}, MITRE ${esc((d.meta.mitre||[]).join(', ')||'n/a')}. Baseline: ${nm(d.baseline)}</div><div class="mono" style="margin:6px 0;word-break:break-word">${esc(e.msg)}</div>
 ${r?`<div class="card"><b>AI triage report</b> <span class="tag ${VD[r.verdict]}">${nm(r.verdict)}</span> <span class="m">${esc(r.technique||'no technique')}, confidence ${r.confidence??'n/a'}, ${esc(r.model||'model n/a')}, ${r.latency_ms??'?'} ms, $${r.cost_usd??'?'}</span><p>${esc(r.summary)}</p>${table(['Evidence','Detail'],ev2(r).map(x=>[`<span class="mono">${esc(x.id)}</span>`,esc(x.text||'')]))}<p><b>Recommended action:</b> ${esc(r.action||'none')}</p><div class="m">Validator: ${r.valid?'passed':'FAILED'} ${esc(r.vnotes||'')}</div>
 ${r.decision?`<div class="row"><b>Decision: ${r.decision}</b> <span class="m">${esc(r.note||'')}</span></div>`:`<div class="row"><input id="dn" placeholder="Note (optional)" style="flex:1"><button class="btn" onclick="decide(${r.id},'approved')">Approve action</button><button class="btn d" onclick="decide(${r.id},'rejected')">Reject</button></div><div class="m">Approving only logs a simulated containment. Nothing is executed on any host.</div>`}
 <textarea id="csv" class="mono" style="width:100%;height:120px;margin-top:8px">${esc(d.summary)}</textarea><button class="btn s" onclick="cp()">Copy incident summary</button></div>`:'<div class="card m">No AI report yet. Run the triage service.</div>'}
 <div class="row"><b>Ground-truth label</b><input id="lb" placeholder="your name" value="${esc(sessionStorage.getItem('lb')||S.user)}" style="width:120px">${['true_positive','false_positive','escalate'].map(v=>`<button class="btn s" onclick="lab(${id},'${v}')">${nm(v)}</button>`).join('')}</div><div class="m">Labels so far: ${d.labels.map(l=>esc(l.labeler)+' = '+nm(l.label)).join(', ')||'none'}</div><div class="row"><button class="btn s" onclick="mc()">Close</button></div>`)};
window.decide=async(rid,dec)=>{const n=$('#dn')?$('#dn').value:'';await act('POST','/reports/'+rid+'/decision',{decision:dec,note:n},'Report '+dec);mc()};
window.lab=async(id,l)=>{const n=$('#lb').value.trim();sessionStorage.setItem('lb',n);await act('POST','/alerts/'+id+'/label',{label:l,labeler:n},'Labelled '+nm(l));openTri(id)};

toast('Connected to live backend');poll();setInterval(poll,2000);
})();
