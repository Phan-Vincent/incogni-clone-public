"""Static, dependency-free operator dashboard."""

DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Privacy Service</title>
<style>
:root{color-scheme:light;font:16px system-ui;background:#f4f7f5;color:#173126}
body{max-width:980px;margin:2.5rem auto;padding:0 1rem}h1{margin-bottom:.25rem}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:1rem}
.card{background:#fff;border:1px solid #d6e1da;border-radius:14px;padding:1.1rem;margin:1rem 0}
button,input{font:inherit;padding:.65rem .8rem;border-radius:8px;border:1px solid #91a59a}
button{background:#176441;color:#fff;cursor:pointer;margin:.2rem}
button:disabled{cursor:wait;opacity:.65}.danger{background:#8b2635}
.muted{color:#53665c}.item{border-top:1px solid #e4ebe7;padding:.75rem 0}
.value{font-size:1.7rem;font-weight:650}.error{color:#8b2635}.toolbar{display:flex;gap:.75rem;align-items:center;justify-content:space-between}
.toolbar [role="status"]{flex:1}.actions{display:flex;align-items:center;gap:.5rem;flex-wrap:wrap}
code{white-space:pre-wrap;word-break:break-word}
@media(max-width:480px){body{margin-top:1rem}.toolbar{align-items:flex-start;flex-direction:column}}
</style>
</head>
<body>
<h1>Personal privacy service</h1>
<p class="muted">Private dashboard for DROP coverage, removals, and actions.</p>
<form class="card" id="login-card">
<label for="password">Dashboard password</label>
<div class="actions">
<input id="password" type="password" autocomplete="current-password" required maxlength="1024">
<button id="login-button" type="submit">Sign in</button>
</div>
<p id="login-message" class="error" role="alert" aria-live="assertive"></p>
</form>
<main id="app" hidden aria-busy="false">
<div class="toolbar">
<span id="global-message" role="status" aria-live="polite"></span>
<div>
<button id="refresh" type="button">Refresh</button>
<button id="logout" type="button">Sign out</button>
</div>
</div>
<div class="grid">
<section class="card"><div class="muted">Findings</div><div class="value" id="findings">Unknown</div></section>
<section class="card"><div class="muted">Removal requests</div><div class="value" id="requests">Unknown</div></section>
<section class="card"><div class="muted">Blocked jobs</div><div class="value" id="blocked">Unknown</div></section>
<section class="card"><div class="muted">California DROP</div><div class="value" id="drop">Unknown</div>
<a href="https://privacy.ca.gov/drop/" rel="noreferrer">Official DROP site</a></section>
</div>
<section class="card"><h2>Safety controls</h2>
<button id="pause" type="button" class="danger">Emergency stop</button>
<button id="resume" type="button">Resume</button>
<span id="safety">Unknown</span></section>
<section class="card"><h2>Actions awaiting approval</h2><div id="approvals">Unknown</div></section>
<section class="card"><h2>Recent jobs</h2><div id="jobs">Unknown</div></section>
</main>
<script>
let csrf="";
class ApiError extends Error{
  constructor(status,message){super(message);this.status=status}
}
const byId=(id)=>document.getElementById(id);
function describeError(body,fallback){
  if(Array.isArray(body.detail))return body.detail.map(item=>item.msg||"Invalid request").join("; ");
  return String(body.detail||fallback);
}
async function request(path,options={}){
  options.headers={...(options.headers||{}),...(csrf?{"X-CSRF-Token":csrf}:{})};
  const response=await fetch(path,options);
  const raw=await response.text();
  let body={};
  if(raw){
    try{body=JSON.parse(raw)}catch(_error){body={detail:"Invalid server response"}}
  }
  if(!response.ok)throw new ApiError(response.status,describeError(body,"Request failed"));
  return body;
}
function setLogin(message=""){
  csrf="";byId("app").hidden=true;byId("login-card").hidden=false;
  byId("login-message").textContent=message;byId("password").focus();
}
function handleError(error){
  if(error instanceof ApiError&&error.status===401){
    setLogin("Your session expired. Sign in again.");
    return;
  }
  byId("global-message").textContent=error.message||"Request failed";
  byId("global-message").className="error";
}
function item(text){
  const node=document.createElement("div");node.className="item";node.textContent=text;return node;
}
function render(status,approvals,jobs){
  byId("findings").textContent=status.findings;byId("requests").textContent=status.requests;
  byId("blocked").textContent=status.blocked_jobs;
  byId("drop").textContent=status.drop_enrolled?"Enrolled":"Not recorded";
  byId("safety").textContent=status.emergency_stop?"Stopped":"Active";
  const actions=byId("approvals");actions.replaceChildren();
  if(!approvals.length)actions.textContent="None.";
  for(const approval of approvals){
    if(approval.expired){
      const row=item(approval.action+" · expired "+approval.expires_at);
      const renew=document.createElement("button");renew.type="button";renew.textContent="Reissue";
      renew.onclick=()=>decide(approval.id,"reissue",renew);row.append(renew);actions.append(row);
      continue;
    }
    const row=item(approval.action+" · expires "+approval.expires_at);
    const yes=document.createElement("button");yes.type="button";yes.textContent="Approve";
    yes.onclick=()=>decide(approval.id,"approve",yes);
    const no=document.createElement("button");no.type="button";no.textContent="Reject";no.className="danger";
    no.onclick=()=>decide(approval.id,"reject",no);row.append(yes,no);actions.append(row);
  }
  const recent=byId("jobs");recent.replaceChildren();
  if(!jobs.length)recent.textContent="None.";
  for(const job of jobs.slice(0,20))recent.append(item(job.kind+" · "+job.status));
}
async function refresh(){
  byId("app").setAttribute("aria-busy","true");
  byId("global-message").textContent="Refreshing…";byId("global-message").className="";
  try{
    const [status,approvals,jobs]=await Promise.all([
      request("/api/status"),request("/api/approvals"),request("/api/jobs")
    ]);
    render(status,approvals,jobs);byId("global-message").textContent="";
  }finally{
    byId("app").setAttribute("aria-busy","false");
  }
}
async function login(event){
  event.preventDefault();
  const button=byId("login-button");button.disabled=true;byId("login-message").textContent="";
  try{
    const body=await request("/api/login",{method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify({password:byId("password").value})});
    csrf=body.csrf_token;await refresh();
    byId("password").value="";byId("login-card").hidden=true;byId("app").hidden=false;
  }catch(error){
    setLogin(error.message||"Sign in failed");
  }finally{
    button.disabled=false;
  }
}
async function mutate(button,path){
  button.disabled=true;byId("global-message").textContent="";
  try{await request(path,{method:"POST"});await refresh()}
  catch(error){handleError(error)}
  finally{button.disabled=false}
}
async function decide(id,decision,button){
  button.disabled=true;byId("global-message").textContent="";
  try{
    await request("/api/approvals/"+encodeURIComponent(id)+"/"+decision,{method:"POST"});
    await refresh();
  }catch(error){handleError(error)}
  finally{button.disabled=false}
}
async function logout(){
  const button=byId("logout");button.disabled=true;
  try{
    await request("/api/logout",{method:"POST"});
    byId("password").value="";setLogin("Signed out.");
  }catch(error){handleError(error)}
  finally{button.disabled=false}
}
async function initialize(){
  try{
    const session=await request("/api/session");csrf=session.csrf_token;await refresh();
    byId("login-card").hidden=true;byId("app").hidden=false;
  }catch(error){
    if(error instanceof ApiError&&error.status===401)setLogin();
    else setLogin("Could not load the dashboard: "+(error.message||"Request failed"));
  }
}
byId("login-card").addEventListener("submit",login);
byId("pause").onclick=()=>mutate(byId("pause"),"/api/pause");
byId("resume").onclick=()=>{
  if(window.confirm("Resume privacy-service execution?"))mutate(byId("resume"),"/api/resume");
};
byId("refresh").onclick=async()=>{
  byId("refresh").disabled=true;
  try{await refresh()}catch(error){handleError(error)}
  finally{byId("refresh").disabled=false}
};
byId("logout").onclick=logout;
initialize();
</script>
</body></html>"""
