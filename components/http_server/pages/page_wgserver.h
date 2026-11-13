/* WireGuard server page templates (CONFIG_WG_SERVER builds only).
 * Streamed in chunks; all changes go through POST /api/wgserver. */

#define WGS_CHUNK_HEAD "<html>\
<head>\
<meta name='viewport' content='width=device-width, initial-scale=1, maximum-scale=1, user-scalable=0'>\
<meta charset='UTF-8'>\
<title>WireGuard Server</title>\
<link rel='icon' href='favicon.png'>\
</head>\
<style>\
* { box-sizing: border-box; margin: 0; padding: 0; }\
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: #e0e0e0; padding: 1rem; min-height: 100vh; line-height: 1.6; }\
h1 { font-size: 1.5rem; font-weight: 600; color: #00d9ff; margin: 0; }\
h2 { font-size: 1.15rem; font-weight: 500; color: #00d9ff; margin: 1.5rem 0 0.75rem 0; padding-bottom: 0.5rem; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
#container { max-width: 760px; margin: 0 auto; padding: 1.5rem; background: rgba(30, 30, 46, 0.9); border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4); }\
table { width: 100%; border-collapse: collapse; }\
td, th { padding: 0.45rem 0.4rem; vertical-align: top; text-align: left; font-size: 0.9rem; }\
th { color: #888; font-weight: 500; border-bottom: 1px solid rgba(0, 217, 255, 0.2); }\
.f td:first-child { color: #888; width: 35%; text-align: right; padding-right: 0.75rem; }\
.p td { border-bottom: 1px solid rgba(255, 255, 255, 0.05); word-break: break-all; }\
input[type='text'], input[type='number'], select { width: 100%; background: rgba(22, 33, 62, 0.6); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; color: #e0e0e0; padding: 0.6rem; font-size: 0.9rem; }\
select option { background: #16213e; color: #e0e0e0; }\
input::placeholder { color: #666; }\
.ok-button { border: none; border-radius: 8px; padding: 0.65rem 1.25rem; font-size: 0.9rem; font-weight: 600; cursor: pointer; width: 100%; margin-top: 0.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; }\
.sb { border: 1px solid #00d9ff; background: none; color: #00d9ff; border-radius: 6px; padding: 0.2rem 0.6rem; font-size: 0.8rem; cursor: pointer; margin: 0 0.2rem 0.2rem 0; }\
.sb.d { border-color: #ff5252; color: #ff5252; }\
pre { background: rgba(22, 33, 62, 0.8); border: 1px solid rgba(0, 217, 255, 0.2); border-radius: 8px; padding: 0.75rem; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; }\
small { display: block; color: #888; font-size: 0.8rem; line-height: 1.4; }\
#msg { margin: 0.75rem 0; font-size: 0.9rem; min-height: 1.2rem; }\
</style>\
<body>\
<div id='container'>\
<div style='display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;'>\
<div style='display: flex; align-items: center;'>\
<a href='/' style='display: inline-block; margin-right: 1rem;'><img src='/favicon.png' alt='Home' style='width: 64px; height: 64px; border: none;'></a>\
<h1>WireGuard Server</h1>\
</div>"

/* Closes the header row and defines the page logic */
#define WGS_CHUNK_SCRIPT "\
</div>\
<script>\
function E(i){return document.getElementById(i);}\
function v(i){return encodeURIComponent(E(i).value.trim());}\
function api(b,cb){var m=E('msg');m.style.color='#00d9ff';m.textContent='Working...';\
fetch('/api/wgserver',{method:'POST',body:b}).then(function(r){return r.json();}).then(function(d){\
m.style.color=d.ok?'#4caf50':'#ff5252';m.textContent=d.msg;if(d.ok&&cb)cb(d);\
}).catch(function(){m.style.color='#ff5252';m.textContent='Request failed';});}\
function qr(d){var c=E('qr');if(!d.qr){c.style.display='none';E('qh').style.display='none';return;}\
var n=d.qrn,s=4,q=4,x=c.getContext('2d');c.width=c.height=(n+2*q)*s;x.fillStyle='#fff';x.fillRect(0,0,c.width,c.height);x.fillStyle='#000';\
for(var i=0;i<n*n;i++){if(parseInt(d.qr[i>>2],16)&(8>>(i&3)))x.fillRect((q+i%n)*s,(q+(i/n|0))*s,s,s);}\
c.style.display='block';E('qh').style.display='block';}\
function show(d,n){if(d.conf){E('conf').textContent=d.conf;E('cn').value=n;E('out').style.display='block';qr(d);}}\
function save(){api('action=settings&enabled='+v('en')+'&port='+v('po')+'&ip='+v('ip')+'&mask='+v('ma')+'&host='+v('ho'),\
function(d){if(d.reboot)setTimeout(function(){location.href='/';},10000);});}\
function add(){var n=E('pn').value.trim();api('action=add&name='+v('pn')+'&pubkey='+v('pk')+'&pip='+v('pi')+'&split='+v('pt')+'&psk='+(v('pg')==2?v('ps'):v('pg')==1?'1':''),function(d){show(d,n);});}\
function pc(n){api('action=conf&name='+n+'&split='+v('pt'),function(d){show(d,n);});}\
function pd(n){if(confirm('Remove peer '+n+'?'))api('action=del&name='+n,function(){location.reload();});}\
function dl(){var a=document.createElement('a');a.href=URL.createObjectURL(new Blob([E('conf').textContent],{type:'text/plain'}));a.download=E('cn').value+'.conf';a.click();}\
</script>"

#define WGS_CHUNK_ADD "\
<h2>Add Client</h2>\
<table class='f'>\
<tr><td>Name</td><td><input type='text' id='pn' maxlength='15' placeholder='e.g. phone'/></td></tr>\
<tr><td>Public Key</td><td><input type='text' id='pk' maxlength='44' placeholder='Optional'/>\
<small>Leave empty to generate a key pair on the router. The private key is then shown once and not stored.</small></td></tr>\
<tr><td>Tunnel IP</td><td><input type='text' id='pi' placeholder='Optional, next free address'/></td></tr>\
<tr><td>Preshared Key</td><td><select id='pg' onchange=\"E('ps').style.display=this.value==2?'block':'none'\"><option value='0'>None</option><option value='1'>Generate</option><option value='2'>Enter key</option></select>\
<input type='text' id='ps' maxlength='44' placeholder='Base64 key (wg genpsk)' style='display:none; margin-top:0.4rem;'/>\
<small>Optional extra secret per client. It is stored on the router and included in the client config.</small></td></tr>\
<tr><td>Client Routes</td><td><select id='pt'><option value='0'>Full tunnel (all traffic)</option><option value='1'>Split tunnel (router networks only)</option></select>\
<small>Also used by the Config buttons above.</small></td></tr>\
<tr><td></td><td><button type='button' class='ok-button' onclick='add()'>Add Client</button></td></tr>\
</table>\
<div id='msg'></div>\
<div id='out' style='display:none;'>\
<h2>Client Config</h2>\
<input type='hidden' id='cn' value='client'/>\
<canvas id='qr' style='display:none; margin:0 auto 0.75rem auto; max-width:100%;'></canvas>\
<small id='qh' style='display:none; text-align:center; margin-bottom:0.75rem;'>Scan with the WireGuard app (Add tunnel, Scan from QR code).</small>\
<pre id='conf'></pre>\
<button type='button' class='ok-button' onclick='dl()'>Download .conf</button>\
<small style='margin-top:0.5rem;'>Import this file in the WireGuard app. Reload the page to refresh the client list.</small>\
</div>\
<div style='margin-top: 1.5rem; text-align: center;'>\
<a href='/' style='padding: 0.6rem 1.5rem; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #fff; border-radius: 8px; text-decoration: none; font-size: 0.9rem; font-weight: 600;'>Home</a>\
</div>\
</div>\
</body>\
</html>"
