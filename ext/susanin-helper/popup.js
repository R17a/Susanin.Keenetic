const $ = function (id) { return document.getElementById(id); };
const DEFAULT_PANEL = "http://192.168.1.1:8087";
let curHost = "";

function norm(h) { return h.replace(/^www\./i, ""); }
function value() { return $("nowww").checked ? norm(curHost) : curHost; }

async function settings() {
  const s = await chrome.storage.local.get(["panelUrl", "token"]);
  return {
    base: (s.panelUrl || DEFAULT_PANEL).replace(/\/+$/, ""),
    token: s.token || ""
  };
}

function headers(token, extra) {
  const h = Object.assign({}, extra || {});
  if (token)
    h["X-Auth-Token"] = token;
  return h;
}

function say(msg, err) {
  $("lst").className = err ? "err" : "";
  $("lst").textContent = msg;
}

async function fetchList(base, token, name) {
  const r = await fetch(base + "/api/list?name=" + name, { headers: headers(token) });
  if (!r.ok)
    throw new Error("HTTP " + r.status);
  const arr = await r.json();
  if (!Array.isArray(arr))
    return null;
  return arr.map(function (x) { return String(x).toLowerCase(); });
}

/* Показываем, где сайт уже лежит: GET /api/list отдаёт голый JSON-массив. */
async function membership() {
  if (!curHost) {
    say("Служебная страница — сайт не выбран", true);
    return;
  }
  const { base, token } = await settings();
  const host = curHost.toLowerCase();
  const bare = norm(host);
  try {
    const res = await Promise.all([
      fetchList(base, token, "vpn_always"),
      fetchList(base, token, "vpn_never")
    ]);
    const has = function (arr) {
      if (!arr)
        return false;
      return arr.indexOf(host) >= 0 || arr.indexOf(bare) >= 0 ||
             arr.indexOf("*." + bare) >= 0 || arr.indexOf("?." + bare) >= 0;
    };
    const a = has(res[0]), n = has(res[1]);
    if (a && n)
      say(curHost + " — в always И в never, проверьте списки", true);
    else if (a)
      say(curHost + " — в always");
    else if (n)
      say(curHost + " — в never");
    else
      say(curHost + " — ни в always, ни в never");
  } catch (e) {
    say("списки не прочитаны: " + e.message, true);
  }
}

async function listOp(list, op) {
  if (!curHost) {
    say("нет текущего сайта", true);
    return;
  }
  const { base, token } = await settings();
  /* При удалении снимаем и «как есть», и без www: пользователь мог добавить
   * сайт раньше в другом виде. */
  const vals = (op === "del" && value() !== curHost) ? [value(), curHost] : [value()];
  try {
    for (let i = 0; i < vals.length; i++) {
      const r = await fetch(base + "/api/list", {
        method: "POST",
        headers: headers(token, { "Content-Type": "application/x-www-form-urlencoded" }),
        body: "list=" + list + "&op=" + op + "&value=" + encodeURIComponent(vals[i])
      });
      const j = await r.json().catch(function () { return {}; });
      if (!r.ok || !j.ok)
        throw new Error(j.error || ("HTTP " + r.status));
    }
    say(curHost + (op === "add" ? " — добавлен в " : " — убран из ") + list);
    membership();
  } catch (e) {
    say("панель отказала: " + e.message, true);
  }
}

chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
  try {
    curHost = new URL(tabs[0].url).hostname;
    $("cur").textContent = curHost;
  } catch (e) {
    curHost = "";
    $("cur").textContent = "Служебная страница";
  }
  membership();
});

$("alAdd").onclick = function () { listOp("vpn_always", "add"); };
$("alDel").onclick = function () { listOp("vpn_always", "del"); };
$("nvAdd").onclick = function () { listOp("vpn_never", "add"); };
$("nvDel").onclick = function () { listOp("vpn_never", "del"); };
$("refresh").onclick = function () { membership(); };

$("save").onclick = async function () {
  let base = $("url").value.trim().replace(/\/+$/, "");
  if (base && !/^https?:\/\//i.test(base))
    base = "http://" + base;
  await chrome.storage.local.set({
    panelUrl: base,
    token: $("tok").value.trim()
  });
  $("st").className = "";
  $("st").textContent = "сохранено";
  membership();
};

$("test").onclick = async function () {
  const { base, token } = await settings();
  try {
    const r = await fetch(base + "/api/status", { headers: headers(token) });
    if (!r.ok)
      throw new Error("HTTP " + r.status);
    const j = await r.json();
    $("st").className = "";
    $("st").textContent = "панель " + (j.version || "ok");
  } catch (e) {
    $("st").className = "err";
    $("st").textContent = "нет связи: " + e.message;
  }
};

(async function init() {
  const s = await chrome.storage.local.get(["panelUrl", "token"]);
  $("url").value = s.panelUrl || DEFAULT_PANEL;
  $("tok").value = s.token || "";
})();
