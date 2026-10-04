#include "fptn-vless/dashboard.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <sstream>
#include <utility>

#include <spdlog/spdlog.h>  // NOLINT(build/include_order)

namespace fptn::vless {

namespace asio = boost::asio;
using asio::ip::tcp;

namespace {

// The page is kept in several pieces: one string literal may not exceed
// about 16 KB in MSVC.
constexpr const char* kHead = R"HTML(<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>fptn-vless</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='14' fill='%232f6fed'/%3E%3Ccircle cx='32' cy='32' r='23' fill='none' stroke='white' stroke-width='5'/%3E%3Ccircle cx='32' cy='32' r='13' fill='none' stroke='white' stroke-width='4'/%3E%3Ccircle cx='32' cy='32' r='5' fill='white'/%3E%3C/svg%3E">
<style>
)HTML";
constexpr const char* kStyle = R"HTML(:root{--bg:#f3f5f8;--card:#fff;--fg:#17202b;--mut:#6b7686;--line:#e3e8ef;--soft:#f6f8fb;--ac:#2f6fed;--acfg:#fff;--acs:#e8efff;--ok:#16a05a;--warn:#d98a00;--bad:#d92d20;--shadow:0 1px 2px rgba(16,24,40,.05),0 1px 3px rgba(16,24,40,.06)}
@media (prefers-color-scheme:dark){:root{--bg:#0f1318;--card:#171c23;--fg:#e8ecf1;--mut:#8e99a8;--line:#262d37;--soft:#1c222b;--ac:#6c9bff;--acfg:#0c1220;--acs:#1d2a44;--ok:#3ccf7b;--warn:#f0b13a;--bad:#ff7466;--shadow:none}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 "Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;overflow:hidden;display:flex;flex-direction:column}
button,input,select{font:inherit;color:inherit}
button{cursor:pointer;border:1px solid var(--line);background:var(--card);border-radius:9px;padding:7px 12px;transition:border-color .15s,background .15s}
button:hover:not(:disabled){border-color:var(--ac)}
button:disabled{opacity:.5;cursor:default}
button.p{background:var(--ac);border-color:var(--ac);color:var(--acfg);font-weight:600}
button.p:hover:not(:disabled){filter:brightness(1.07)}
button.ghost{background:transparent}
button.sm{padding:4px 10px;font-size:13px}
[hidden]{display:none!important}
input,select{background:var(--card);border:1px solid var(--line);border-radius:9px;padding:7px 10px;min-width:0}
input:focus,select:focus,button:focus-visible{outline:2px solid var(--ac);outline-offset:1px}
.mut{color:var(--mut)}
.top{display:flex;align-items:center;gap:14px;padding:12px 20px;background:var(--card);border-bottom:1px solid var(--line);box-shadow:var(--shadow)}
.logo{width:34px;height:34px;flex:none}
.top h1{font-size:16px;margin:0;line-height:1.1}
.pill{display:inline-flex;align-items:center;gap:7px;font-size:13px;color:var(--mut);margin-top:2px}
.dot{width:9px;height:9px;border-radius:50%;background:var(--mut);flex:none}
.dot.ok{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 25%,transparent)}
.dot.bad{background:var(--bad)}.dot.work{background:var(--warn);animation:pulse 1s infinite}
@keyframes pulse{50%{opacity:.35}}
.spacer{flex:1}
.banner{margin:12px 20px 0;padding:9px 14px;border-radius:10px;background:color-mix(in srgb,var(--bad) 12%,var(--card));border:1px solid color-mix(in srgb,var(--bad) 35%,var(--line));color:var(--bad)}
.grid{flex:1;min-height:0;display:grid;grid-template-columns:minmax(300px,1fr) 400px;gap:16px;padding:16px 20px 18px}
.panel,.card{background:var(--card);border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
.left{display:flex;flex-direction:column;min-height:0}
.phead{display:flex;align-items:center;gap:10px;padding:14px 16px 10px;flex-wrap:wrap}
.phead h2{font-size:15px;margin:0}.phead .count{color:var(--mut);font-weight:400;margin-left:4px}
.list{flex:1;min-height:0;overflow:auto;padding:0 8px 8px}
.row{display:grid;grid-template-columns:minmax(80px,1.2fr) minmax(70px,1fr) 78px 118px;align-items:center;gap:10px;padding:9px 10px;border-radius:10px;border:1px solid transparent;cursor:pointer}
.row:hover{background:var(--soft)}
.row.act{background:var(--acs);border-color:color-mix(in srgb,var(--ac) 45%,transparent)}
.row.off{opacity:.55}
.name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.name small{font-weight:400;color:var(--mut);margin-left:6px}
.bar{height:6px;border-radius:3px;background:var(--line);overflow:hidden}.bar i{display:block;height:100%;border-radius:3px;background:var(--ok)}
.bar i.mid{background:var(--warn)}.bar i.bad{background:var(--bad)}
.ms{text-align:right;font-variant-numeric:tabular-nums}
.act-cell{text-align:right}
.tag{display:inline-block;padding:2px 9px;border-radius:99px;font-size:12px;font-weight:600;background:var(--ac);color:var(--acfg)}
.row button{opacity:0;padding:4px 10px;font-size:13px}.row:hover button{opacity:1}
.pfoot{padding:9px 16px 10px;border-top:1px solid var(--line);font-size:13px;color:var(--mut)}
#check{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-height:20px}
.pfoot pre{height:76px;margin:6px 0 0;overflow:auto;font:12px/1.5 ui-monospace,Consolas,monospace;white-space:pre-wrap;background:var(--soft);border-radius:8px;padding:6px 10px}
.right{display:flex;flex-direction:column;gap:12px;min-height:0;overflow:auto;padding-right:2px}
.card{padding:14px 16px;flex:none}
.card h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);margin:0 0 9px;font-weight:600}
.card h3+.seg{margin-top:0}
.seg{display:grid;grid-auto-flow:column;grid-auto-columns:1fr;background:var(--soft);border:1px solid var(--line);border-radius:10px;padding:3px;gap:3px}
.seg button{border:0;background:transparent;border-radius:7px;padding:6px 8px;font-size:13px}
.seg button.on{background:var(--card);box-shadow:0 1px 2px rgba(16,24,40,.15);color:var(--ac);font-weight:600}
.seg.mini{display:inline-grid}
.hint{font-size:12.5px;color:var(--mut);margin:7px 0 12px}
.gap{height:6px}
.line{display:flex;gap:8px;align-items:center}
.line input[type=number]{width:110px}.line .grow{flex:1}
input.link{width:100%;font:12.5px ui-monospace,Consolas,monospace;margin-top:8px;text-overflow:ellipsis}
.fw{margin-top:10px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:13px}
.fw .s-ok{color:var(--ok)}.fw .s-closed{color:var(--warn)}
.overlay{position:fixed;inset:0;background:color-mix(in srgb,var(--bg) 82%,transparent);backdrop-filter:blur(6px);display:flex;align-items:center;justify-content:center;padding:20px;z-index:5}
.dialog{width:min(560px,100%);background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 20px 50px rgba(16,24,40,.25)}
.dialog h2{margin:0 0 4px;font-size:18px}
.dialog textarea{width:100%;height:120px;margin-top:12px;font:12.5px ui-monospace,Consolas,monospace;border:1px solid var(--line);border-radius:10px;padding:10px;background:var(--card);color:var(--fg);resize:none}
.dialog .err{color:var(--bad);min-height:20px;margin-top:6px}
.dialog label{display:flex;gap:8px;align-items:flex-start;margin-top:10px;color:var(--mut)}
@media (max-width:900px){body{overflow:auto;height:auto}.grid{grid-template-columns:1fr;flex:none}.list{max-height:50vh}.right{overflow:visible}}
@media (max-height:640px){.top{padding:8px 16px}.grid{padding:10px 16px;gap:12px}.card{padding:10px 14px}.hint{display:none}.pfoot pre{height:52px}}
)HTML";
constexpr const char* kBody = R"HTML(</style></head><body>
<header class="top">
  <svg class="logo" viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#2f6fed"/><circle cx="32" cy="32" r="23" fill="none" stroke="#fff" stroke-width="5"/><circle cx="32" cy="32" r="13" fill="none" stroke="#fff" stroke-width="4"/><circle cx="32" cy="32" r="5" fill="#fff"/></svg>
  <div><h1>fptn-vless</h1><div class="pill"><span id="dot" class="dot"></span><span id="status">…</span></div></div>
  <div class="spacer"></div>
  <button id="forget" class="ghost sm" hidden>Сменить токен</button>
  <button id="main" class="p">Подключиться</button>
</header>
<div id="banner" class="banner" hidden></div>
<div class="grid">
  <section class="panel left">
    <div class="phead"><h2>Серверы<span id="count" class="count"></span></h2><div class="spacer"></div>
      <div class="seg mini" id="sort"><button data-v="ping" class="on">По пингу</button><button data-v="list">По списку</button></div>
      <button id="rescan" class="sm">↻ Замерить</button></div>
    <div id="servers" class="list"></div>
    <div class="pfoot"><div id="check"></div><pre id="events"></pre></div>
  </section>
  <aside class="right">
    <section class="card">
      <h3>Режим подключения</h3>
      <div class="seg" id="mode"><button data-v="best">Лучший по пингу</button><button data-v="selected">Только выбранный</button></div>
      <div id="mode_hint" class="hint"></div>
      <h3>Если сервер перестал отвечать</h3>
      <div class="seg" id="onfail"><button data-v="switch">Перейти на другой</button><button data-v="nothing">Ничего не делать</button></div>
    </section>
    <section class="card">
      <h3>Ссылка для телефона и других ПК</h3>
      <div id="link_empty" class="mut">Появится после подключения.</div>
      <div id="link_box" hidden>
        <div class="line"><select id="host" class="grow"></select><button id="copy" class="p">Копировать</button></div>
        <input id="link" class="link" readonly>
      </div>
    </section>
    <section class="card">
      <h3>Порт и доступ из сети</h3>
      <div class="line"><input id="port" type="number" min="1" max="65535" inputmode="numeric"><button id="apply">Применить</button><span id="port_msg" class="mut"></span></div>
      <div id="fw" class="fw" hidden><span id="fw_text"></span><button id="fw_add" class="sm p" hidden>Открыть порт в брандмауэре</button><button id="fw_check" class="sm ghost" hidden>Проверить</button></div>
    </section>
  </aside>
</div>
<div id="overlay" class="overlay" hidden>
  <div class="dialog">
    <h2>Токен доступа FPTN</h2>
    <div class="mut">Вставьте токен целиком. Пробелы и переносы строк не мешают.</div>
    <textarea id="token" placeholder="fptnb:…" spellcheck="false"></textarea>
    <label><input type="checkbox" id="remember" checked><span>Запомнить на этом компьютере (хранится зашифрованным для вашей учётной записи Windows)</span></label>
    <div id="token_msg" class="err"></div>
    <div class="line"><div class="spacer"></div><button id="send" class="p">Загрузить серверы</button></div>
  </div>
</div>
)HTML";
constexpr const char* kScript = R"HTML(<script>
const $=id=>document.getElementById(id);
let S=null, sortBy='ping', lastSig='';
try{sortBy=localStorage.getItem('sort')||'ping';}catch(e){}
async function post(path,body){
  try{await fetch(path,{method:'POST',headers:{'X-Requested-With':'fptn'},body:body||''});}catch(e){}
  refresh();
}
function pingClass(ms){return ms<800?'':(ms<2000?'mid':'bad');}
function working(){return !!S.busy||S.phase==='scanning'||S.phase==='connecting';}
function setSeg(id,val,disabled){
  document.querySelectorAll('#'+id+' button').forEach(b=>{b.classList.toggle('on',b.dataset.v===val);b.disabled=!!disabled;});
}
function render(){
  if(!S) return;
  const conn=S.phase==='connected', has=S.servers.length>0, work=working();
  // status
  const dot=$('dot'); dot.className='dot'+(work?' work':(S.tunnel_down?' bad':(conn?' ok':'')));
  let st='Не подключено';
  if(S.phase==='no_token') st='Нужен токен';
  else if(work) st=S.busy||S.message||'Работаю…';
  else if(conn){const a=S.servers[S.active_index]; st=(S.tunnel_down?'Связь потеряна · ':'Подключено · ')+(a?a.name:'');}
  else if(has) st='Не подключено';
  $('status').textContent=st;
  const b=$('main'); b.textContent=conn?'Отключиться':'Подключиться'; b.className=conn?'':'p'; b.disabled=work||!has;
  $('forget').hidden=S.phase==='no_token'; $('forget').disabled=work;
  const note=S.notice||(S.phase==='ready'?S.message:'');
  $('banner').hidden=!note; $('banner').textContent=note||'';
  $('overlay').hidden=S.phase!=='no_token'; $('token_msg').textContent=S.phase==='no_token'?(S.message||''):''; $('send').disabled=work;
  // settings
  setSeg('mode',S.mode,false);
  const fo=S.failover_available;
  setSeg('onfail',S.switch_on_failure?'switch':'nothing',!fo);
  $('mode_hint').textContent=S.mode==='best'
    ?'Программа держится самого быстрого сервера и сама переходит на лучший, когда он меняется.'
    :'Программа остаётся на выбранном вами сервере'+(S.selected?(' ('+S.selected+')'):'')+' и не ищет более быстрый.';
  // link
  $('link_empty').hidden=conn; $('link_box').hidden=!conn;
  const sel=$('host');
  if(sel.options.length!==S.links.length){sel.innerHTML='';S.links.forEach((l,i)=>{const o=document.createElement('option');o.value=i;o.textContent=l.host;sel.appendChild(o);});}
  const li=Math.min(+sel.value||0,S.links.length-1); $('link').value=S.links[li]?S.links[li].url:'';
  // port + firewall
  const pi=$('port');
  if(document.activeElement!==pi && pi.dataset.dirty!=='1') pi.value=S.port;
  portCheck();
  const fw=$('fw'); fw.hidden=S.firewall==='unsupported';
  const t=$('fw_text');
  t.className=''; 
  if(S.firewall==='open'){t.textContent='✓ Порт открыт в брандмауэре Windows';t.className='s-ok';}
  else if(S.firewall==='closed'){t.textContent='Порт закрыт для других устройств сети.';t.className='s-closed';}
  else {t.textContent='Состояние брандмауэра неизвестно.';}
  $('fw_add').hidden=S.firewall==='open'; $('fw_add').disabled=work;
  $('fw_check').hidden=S.firewall==='open'&&false; $('fw_check').disabled=work;
  // servers
  $('count').textContent=has?(' · '+S.servers.length):'';
  $('rescan').disabled=work||!has;
  document.querySelectorAll('#sort button').forEach(x=>x.classList.toggle('on',x.dataset.v===sortBy));
  renderServers(conn,work);
  $('check').textContent=S.check||(conn?'':'Нажмите «Замерить», чтобы обновить отклик.');
  const ev=$('events'),bottom=ev.scrollTop+ev.clientHeight>=ev.scrollHeight-20;
  const text=S.events.join('\n'); if(ev.textContent!==text){ev.textContent=text; if(bottom) ev.scrollTop=ev.scrollHeight;}
}
function renderServers(conn,work){
  let idx=S.servers.map((s,i)=>i);
  if(sortBy==='ping') idx.sort((a,b)=>{const pa=S.servers[a].ping,pb=S.servers[b].ping;
    if(pa===null&&pb===null) return a-b; if(pa===null) return 1; if(pb===null) return -1; return pa-pb||a-b;});
  const best=Math.min(...S.servers.filter(s=>s.ping!==null).map(s=>s.ping));
  const sig=JSON.stringify([idx,S.servers.map(s=>[s.ping,s.probed]),S.active_index,S.selected,S.mode,conn,work]);
  if(sig===lastSig) return; lastSig=sig;
  const box=$('servers'), keep=box.scrollTop; box.innerHTML='';
  idx.forEach(i=>{
    const s=S.servers[i], active=conn&&i===S.active_index, off=s.probed&&s.ping===null;
    const r=document.createElement('div'); r.className='row'+(active?' act':'')+(off?' off':'');
    const n=document.createElement('div'); n.className='name'; n.textContent=s.name;
    if(S.mode==='selected'&&S.selected===s.name&&!active){const g=document.createElement('small');g.textContent='выбран';n.appendChild(g);}
    const bar=document.createElement('div'); bar.className='bar';
    if(s.ping!==null){const f=document.createElement('i'); f.className=pingClass(s.ping); f.style.width=Math.max(6,Math.round(100*best/Math.max(s.ping,best)))+'%'; bar.appendChild(f);}
    const ms=document.createElement('div'); ms.className='ms'+(s.ping===null?' mut':''); ms.textContent=!s.probed?'…':(s.ping===null?'нет ответа':s.ping+' мс');
    const cell=document.createElement('div'); cell.className='act-cell';
    if(active){const tg=document.createElement('span');tg.className='tag';tg.textContent='подключён';cell.appendChild(tg);}
    else if(!off){const bt=document.createElement('button');bt.textContent='Подключиться';bt.disabled=work;bt.onclick=ev=>{ev.stopPropagation();post('/api/connect?i='+i);};cell.appendChild(bt);}
    r.append(n,bar,ms,cell);
    if(!active&&!off&&!work) r.onclick=()=>post('/api/connect?i='+i);
    box.appendChild(r);
  });
  box.scrollTop=keep;
}
function portCheck(){
  const v=$('port').value.trim(), n=+v, ok=/^\d{1,5}$/.test(v)&&n>=1&&n<=65535;
  let msg='';
  if(!ok) msg='1–65535'; else if(S&&n===S.reserved_port) msg='занят панелью';
  $('port_msg').textContent=msg;
  $('apply').disabled=!ok||!S||n===S.port||n===S.reserved_port||working();
}
async function refresh(){
  try{const r=await fetch('/api/state');S=await r.json();render();}
  catch(e){$('status').textContent='Программа не отвечает (закрыта?)';$('dot').className='dot bad';}
}
document.querySelectorAll('#mode button').forEach(b=>b.onclick=()=>{S.mode=b.dataset.v;render();post('/api/mode?value='+b.dataset.v);});
document.querySelectorAll('#onfail button').forEach(b=>b.onclick=()=>{S.switch_on_failure=b.dataset.v==='switch';render();post('/api/onfail?value='+b.dataset.v);});
document.querySelectorAll('#sort button').forEach(b=>b.onclick=()=>{sortBy=b.dataset.v;try{localStorage.setItem('sort',sortBy);}catch(e){}lastSig='';render();});
$('main').onclick=()=>{if(S.phase==='connected') post('/api/disconnect'); else post('/api/connect?auto=1');};
$('rescan').onclick=()=>post('/api/rescan');
$('forget').onclick=()=>{if(confirm('Отключиться и удалить сохранённый токен?')) post('/api/forget');};
$('send').onclick=()=>{const t=$('token').value; if(!t.trim()) return; post('/api/token?remember='+($('remember').checked?1:0),t); $('token').value='';};
$('host').onchange=render;
$('copy').onclick=async()=>{const t=$('link').value;try{await navigator.clipboard.writeText(t);}catch(e){$('link').select();document.execCommand('copy');}$('copy').textContent='Скопировано ✓';setTimeout(()=>$('copy').textContent='Копировать',1300);};
$('port').oninput=()=>{$('port').dataset.dirty='1';portCheck();};
$('port').onkeydown=e=>{if(e.key==='Enter'&&!$('apply').disabled) $('apply').click();};
$('apply').onclick=()=>{post('/api/port?value='+$('port').value.trim());$('port').dataset.dirty='';};
$('fw_add').onclick=()=>post('/api/firewall'); $('fw_check').onclick=()=>post('/api/firewall_check');
refresh(); setInterval(refresh,1500);
</script></body></html>
)HTML";

const std::string& Page() {
  static const std::string page =
      std::string(kHead) + kStyle + kBody + kScript;
  return page;
}

std::string Response(int code,
    const char* reason,
    const char* type,
    const std::string& body) {
  std::ostringstream out;
  out << "HTTP/1.1 " << code << ' ' << reason << "\r\n"
      << "Content-Type: " << type << "\r\n"
      << "Content-Length: " << body.size() << "\r\n"
      << "Cache-Control: no-store\r\n"
      << "X-Content-Type-Options: nosniff\r\n"
      << "Connection: close\r\n\r\n"
      << body;
  return out.str();
}

std::string Lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
      [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return s;
}

// Value of a header (case-insensitive name), "" if absent.
std::string Header(const std::string& head, const std::string& name) {
  std::istringstream in(head);
  std::string line;
  std::getline(in, line);  // request line
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }
    const auto colon = line.find(':');
    if (colon == std::string::npos) {
      continue;
    }
    if (Lower(line.substr(0, colon)) == Lower(name)) {
      std::string value = line.substr(colon + 1);
      const auto first = value.find_first_not_of(" \t");
      return first == std::string::npos ? std::string() : value.substr(first);
    }
  }
  return {};
}

}  // namespace

Dashboard::Dashboard(asio::io_context& ioc, std::uint16_t port, DashboardApi api)
    : ioc_(ioc), port_(port), api_(std::move(api)), acceptor_(ioc) {}

Dashboard::~Dashboard() { Stop(); }

bool Dashboard::Start() {
  boost::system::error_code ec;
  const tcp::endpoint endpoint(asio::ip::make_address("127.0.0.1"), port_);
  acceptor_.open(endpoint.protocol(), ec);
  if (!ec) {
    acceptor_.set_option(tcp::acceptor::reuse_address(true), ec);
  }
  if (!ec) {
    acceptor_.bind(endpoint, ec);
  }
  if (!ec) {
    acceptor_.listen(16, ec);
  }
  if (ec) {
    SPDLOG_WARN("dashboard: cannot listen on 127.0.0.1:{}: {}", port_,
        ec.message());
    return false;
  }
  DoAccept();
  return true;
}

void Dashboard::Stop() {
  boost::system::error_code ignored;
  acceptor_.close(ignored);
}

std::string Dashboard::Handle(
    const std::string& head, const std::string& body) const {
  std::istringstream first(head);
  std::string method;
  std::string target;
  first >> method >> target;
  if (method.empty() || target.empty()) {
    return Response(400, "Bad Request", "text/plain", "bad request");
  }

  // DNS-rebinding guard: only our own address as the Host.
  const std::string host = Lower(Header(head, "Host"));
  const std::string port = std::to_string(port_);
  if (host != "127.0.0.1:" + port && host != "localhost:" + port) {
    return Response(403, "Forbidden", "text/plain", "forbidden");
  }

  std::string path = target;
  std::string query;
  if (const auto q = target.find('?'); q != std::string::npos) {
    path = target.substr(0, q);
    query = target.substr(q + 1);
  }

  if (method == "GET") {
    if (path == "/" || path == "/index.html") {
      return Response(200, "OK", "text/html; charset=utf-8", Page());
    }
    if (path == "/api/state") {
      return Response(200, "OK", "application/json; charset=utf-8",
          api_.state_json ? api_.state_json() : "{}");
    }
    return Response(404, "Not Found", "text/plain", "not found");
  }

  if (method == "POST") {
    // CSRF guard: a foreign web page cannot add this header cross-origin.
    if (Header(head, "X-Requested-With") != "fptn") {
      return Response(403, "Forbidden", "text/plain", "forbidden");
    }
    constexpr const char kPrefix[] = "/api/";
    if (path.rfind(kPrefix, 0) != 0 || !api_.post) {
      return Response(404, "Not Found", "text/plain", "not found");
    }
    switch (api_.post(path.substr(sizeof(kPrefix) - 1), query, body)) {
      case 202:
        return Response(202, "Accepted", "text/plain", "accepted");
      case 400:
        return Response(400, "Bad Request", "text/plain", "bad request");
      case 409:
        return Response(409, "Conflict", "text/plain", "busy");
      default:
        return Response(404, "Not Found", "text/plain", "not found");
    }
  }
  return Response(405, "Method Not Allowed", "text/plain", "method not allowed");
}

namespace {

// One request: read the head, answer, close.
class DashboardConnection : public std::enable_shared_from_this<DashboardConnection> {
 public:
  DashboardConnection(tcp::socket socket, const Dashboard& dashboard)
      : socket_(std::move(socket)), dashboard_(dashboard) {}

  void Start() {
    auto self = shared_from_this();
    asio::async_read_until(socket_, asio::dynamic_buffer(buffer_, kMaxHead),
        "\r\n\r\n",
        [self](const boost::system::error_code& ec, std::size_t n) {
          if (ec) {
            return;
          }
          self->head_size_ = n;
          self->ReadBody();
        });
  }

 private:
  static constexpr std::size_t kMaxHead = 16 * 1024;
  static constexpr std::size_t kMaxBody = 1024 * 1024;  // a token can be huge

  void ReadBody() {
    const std::string head = buffer_.substr(0, head_size_);
    std::size_t length = 0;
    const std::string text = Header(head, "Content-Length");
    if (!text.empty()) {
      length = static_cast<std::size_t>(std::strtoull(text.c_str(), nullptr, 10));
    }
    if (length > kMaxBody) {
      Reply(Response(413, "Payload Too Large", "text/plain", "too large"));
      return;
    }
    const std::size_t have = buffer_.size() - head_size_;
    if (have >= length) {
      Finish();
      return;
    }
    auto self = shared_from_this();
    asio::async_read(socket_,
        asio::dynamic_buffer(buffer_, kMaxHead + kMaxBody),
        asio::transfer_exactly(length - have),
        [self](const boost::system::error_code& ec, std::size_t) {
          if (!ec) {
            self->Finish();
          }
        });
  }

  void Finish() {
    const std::string head = buffer_.substr(0, head_size_);
    const std::string body = buffer_.substr(head_size_);
    Reply(dashboard_.Handle(head, body));
  }

  void Reply(std::string response) {
    response_ = std::move(response);
    auto self = shared_from_this();
    asio::async_write(socket_, asio::buffer(response_),
        [self](const boost::system::error_code&, std::size_t) {
          boost::system::error_code ignored;
          self->socket_.shutdown(tcp::socket::shutdown_both, ignored);
        });
  }

  tcp::socket socket_;
  const Dashboard& dashboard_;
  std::string buffer_;
  std::size_t head_size_ = 0;
  std::string response_;
};

}  // namespace

void Dashboard::DoAccept() {
  acceptor_.async_accept(
      [this](const boost::system::error_code& ec, tcp::socket socket) {
        if (ec == asio::error::operation_aborted) {
          return;
        }
        if (!ec) {
          std::make_shared<DashboardConnection>(std::move(socket), *this)
              ->Start();
        }
        DoAccept();
      });
}

}  // namespace fptn::vless
