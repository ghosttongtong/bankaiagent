/* ============================================================================
 * 手机银行 App 前端(渠道 app)
 *
 * ★ 这个文件里**没有一行业务判断**。
 *   它只做三件事:把用户的话发给网关、把网关的回复渲染出来、把用户的结构化动作回传。
 *   哪句话该被拦、要不要人脸、能不能挂失 —— 全部由服务端的策略引擎决定。
 *
 *   这条边界很重要:如果前端自己判断"这句话像是挂失,我直接显示已冻结",
 *   那就等于在客户端复制了一套业务逻辑 —— 两套逻辑迟早会不一致,
 *   而用户会在 App 上看到"已冻结"、在人工坐席那里听到"其实没冻"。
 * ========================================================================== */

const CHANNEL = "app";

// ---- 会话:同一次连续对话共用一个 sessionId(服务端按会话维护上下文) ----
const SESSION_KEY = "bank-agent-session";
const sessionId = (() => {
  const existing = sessionStorage.getItem(SESSION_KEY);
  if (existing) return existing;
  const fresh = `web_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  sessionStorage.setItem(SESSION_KEY, fresh);
  return fresh;
})();
/** 当前这段对话的标题。刷新后从会话记录恢复,用来标明「还是同一段」 */
let sessionTitle = "";

// ---- DOM ----
const $ = (id) => document.getElementById(id);
const messagesEl = $("messages");
const paneChat = $("pane-chat");
const paneAudit = $("pane-audit");
const paneHistory = $("pane-history");
const historyBody = $("history-body");
const auditBody = $("audit-body");
const composer = $("composer");
const inputEl = $("input");
const formEl = $("form");
const sendBtn = $("send");
const btnBack = $("btn-back");
const btnAudit = $("btn-audit");
const btnHistory = $("btn-history");
const btnMenu = $("btn-menu");
const appbarSub = $("appbar-sub");
const drawerMask = $("drawer-mask");
const drawerBody = $("drawer-body");
const drawerName = $("drawer-name");
const drawerSub = $("drawer-sub");
const btnDrawerClose = $("btn-drawer-close");

let busy = false;
let profile = null;
/** 当前等待用户处理的动作(确认 / 强验证),来自最近一次回复 */
let pending = null;

// ============================================================================
// 网关调用
// ============================================================================

async function post(path, body) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error ?? `请求失败(${res.status})`);
  return data;
}

async function get(path) {
  const res = await fetch(path);
  const data = await res.json();
  if (!res.ok || data.ok === false) throw new Error(data.error ?? `请求失败(${res.status})`);
  return data;
}

const sendText = (text) =>
  post(`/api/channels/${CHANNEL}/messages`, { text, sessionId }).then((d) => d.turn);

const sendAction = (action) =>
  post(`/api/channels/${CHANNEL}/actions`, { sessionId, action }).then((d) => d.turn);

// ============================================================================
// 时间
// ============================================================================

function tickClock() {
  const d = new Date();
  const el = $("clock");
  if (el) el.textContent = `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
}
tickClock();
setInterval(tickClock, 20000);

// ============================================================================
// 左侧抽屉:常用服务 / 我的卡片 / 账户概览
//
// ★ 抽屉只是这些入口的"容器",里面的每一项仍然只是发一句话给网关 ——
//   与对话里的按钮完全同一条路,前端不做任何业务判断。
//   遮罩点击 / 关闭按钮 / Esc 都能收起;在抽屉里点了任何入口,先收起再办。
// ============================================================================

function openDrawer() {
  drawerMask.hidden = false;
  void refreshDesk();
}

function closeDrawer() {
  drawerMask.hidden = true;
  if (!paneChat.hidden) inputEl.focus();
}

btnMenu.addEventListener("click", openDrawer);
btnDrawerClose.addEventListener("click", closeDrawer);
drawerMask.addEventListener("click", (e) => {
  if (e.target === drawerMask) closeDrawer();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !drawerMask.hidden) closeDrawer();
});
// 抽屉里点任何可操作的入口(按钮 / 小卡片),先把抽屉收起来
drawerBody.addEventListener("click", (e) => {
  if (e.target.closest("[data-keep-open]")) return;
  if (e.target.closest("button, .mini-card")) closeDrawer();
});

// ============================================================================
// 渲染:文本
// ============================================================================

/**
 * 把 Agent 的纯文本回复渲染成安全的 DOM。
 *
 * ★ 刻意不用 innerHTML 拼字符串:回复里会包含用户自己说过的话
 *   (比如收款人姓名、备注),而备注是本项目明确的**注入载体**。
 *   在这里用 innerHTML,等于把服务端辛苦做的注入防御在展示层又开了一个口子。
 *   全部走 textContent,只对 `**加粗**` 与 `★` 做一次极小的白名单标记。
 */
function renderText(raw) {
  const frag = document.createDocumentFragment();
  const lines = String(raw ?? "").split("\n");

  lines.forEach((line, i) => {
    if (i > 0) frag.appendChild(document.createTextNode("\n"));
    // 只认 **...** 这一种标记,不解析任何 HTML
    const parts = line.split(/(\*\*[^*]+\*\*)/g);
    for (const part of parts) {
      if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
        const b = document.createElement("span");
        b.className = "md-strong";
        b.textContent = part.slice(2, -2);
        frag.appendChild(b);
      } else if (part) {
        frag.appendChild(document.createTextNode(part));
      }
    }
  });

  return frag;
}

function addMessage({ role, text, variant, stack }) {
  const wrap = document.createElement("div");
  wrap.className = `msg ${role}`;

  const avatar = document.createElement("div");
  avatar.className = "avatar";
  const icon = document.createElement("i");
  icon.className = role === "user" ? "ri-user-3-line" : "ri-robot-2-line";
  icon.setAttribute("aria-hidden", "true");
  avatar.appendChild(icon);
  wrap.appendChild(avatar);

  if (stack) {
    wrap.appendChild(stack);
  } else {
    const bubble = document.createElement("div");
    bubble.className = `bubble${variant ? ` ${variant}` : ""}`;
    bubble.appendChild(renderText(text));
    wrap.appendChild(bubble);
  }

  messagesEl.appendChild(wrap);
  if (role === "agent") makeCollapsible(wrap);
  scrollMsgToStart(wrap);
  return wrap;
}

/**
 * 长回复默认收起:先读到结论,细节想看再展开。
 * 只折叠展示高度,一个字都不删 —— 需要核对全文的人随时能打开。
 */
function makeCollapsible(wrap) {
  const stack = wrap.querySelector(".stack");
  const hasRich = Boolean(stack?.querySelector(".lr, .bill-chart, .ui-card, .visual, .quiz-step"));
  for (const bubble of wrap.querySelectorAll(".bubble")) {
    const text = bubble.textContent ?? "";
    const blocks = bubble.querySelectorAll("p, br, li").length;
    const minLen = hasRich ? 72 : 280;
    const minBlocks = hasRich ? 4 : 8;
    if (text.length < minLen && blocks < minBlocks) continue;
    bubble.classList.add("is-collapsible", "is-collapsed");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "bubble-more";
    btn.textContent = "展开全文";
    btn.setAttribute("aria-expanded", "false");
    btn.addEventListener("click", () => {
      const collapsed = bubble.classList.toggle("is-collapsed");
      btn.textContent = collapsed ? "展开全文" : "收起";
      btn.setAttribute("aria-expanded", String(!collapsed));
    });
    bubble.after(btn); // 放在气泡外:折叠时按钮自己不能被遮罩盖住
  }
}

/**
 * 反诈警示卡。
 *
 * 数据是服务端反诈模块给出的结构化块(headline / scriptBreaker / 核实清单),
 * 前端只做视觉强调 —— 提醒该不该出现、说什么,都不在这里决定。
 * 之所以从正文里抽出来单独画:防骗信息混在长段文字里,恰好是最容易被滑过去的那种。
 */
function renderFraudNotice(fraud) {
  if (!fraud) return null;
  const questions = fraud.questions ?? [];
  if (!fraud.headline && !fraud.scriptBreaker && questions.length === 0) return null;

  const box = document.createElement("div");
  box.className = "fraud";
  box.setAttribute("role", "alert"); // 警示应当被辅助技术优先读到

  const head = document.createElement("div");
  head.className = "fraud-head";
  head.innerHTML = '<i class="ri-alarm-warning-line" aria-hidden="true"></i>防骗提醒';
  box.appendChild(head);

  if (fraud.headline) {
    const h = document.createElement("div");
    h.className = "fraud-headline";
    h.textContent = fraud.headline;
    box.appendChild(h);
  }
  if (fraud.scriptBreaker) {
    const s = document.createElement("div");
    s.className = "fraud-break";
    s.innerHTML = '<i class="ri-double-quotes-l" aria-hidden="true"></i>';
    s.appendChild(document.createTextNode(fraud.scriptBreaker));
    box.appendChild(s);
  }
  if (questions.length > 0) {
    const cap = document.createElement("div");
    cap.className = "fraud-cap";
    cap.textContent = "转账前请先核实:";
    box.appendChild(cap);
    const ul = document.createElement("ul");
    ul.className = "fraud-questions";
    for (const q of questions) {
      const li = document.createElement("li");
      li.textContent = q;
      ul.appendChild(li);
    }
    box.appendChild(ul);
  }
  if (fraud.coolDownSeconds > 0) {
    const c = document.createElement("div");
    c.className = "fraud-cool";
    c.innerHTML = `<i class="ri-timer-line" aria-hidden="true"></i>请花 ${fraud.coolDownSeconds} 秒核实对方身份,再决定是否继续。`;
    box.appendChild(c);
  }
  if (fraud.offerHumanSupport) {
    const f = document.createElement("div");
    f.className = "fraud-foot";
    f.innerHTML = '<i class="ri-customer-service-2-line" aria-hidden="true"></i>无法确认对方身份时,可联系我行反诈专员协助核实。';
    box.appendChild(f);
  }
  return box;
}

function renderCard(card) {
  if (!card) return null;
  const box = document.createElement("div");
  box.className = "ui-card";

  const head = document.createElement("div");
  head.className = "ui-card-head";
  head.innerHTML = '<i class="ri-file-list-3-line" aria-hidden="true"></i>';
  head.appendChild(document.createTextNode(card.title ?? "请确认"));
  box.appendChild(head);

  const body = document.createElement("div");
  body.className = "ui-card-body";
  for (const f of card.fields ?? []) {
    const row = document.createElement("div");
    row.className = `ui-row${f.emphasis ? " emph" : ""}`;
    const label = document.createElement("div");
    label.className = "ui-row-label";
    label.textContent = f.label;
    const value = document.createElement("div");
    value.className = "ui-row-value";
    value.textContent = f.value;
    row.append(label, value);
    body.appendChild(row);
  }
  box.appendChild(body);

  if (card.warning) {
    const w = document.createElement("div");
    w.className = "ui-card-warn";
    w.appendChild(renderText(card.warning));
    box.appendChild(w);
  }
  if (card.reversibility) {
    const r = document.createElement("div");
    r.className = "ui-card-rev";
    r.textContent = `可撤销:${card.reversibility}`;
    box.appendChild(r);
  }
  return box;
}

/**
 * 裁决理由里只有「拒绝 / 需要升级介入」才值得摆到界面上。
 * 放行类理由(白名单、信任抵扣等)由风险因子那一段去讲,不在这里重复一遍。
 */
function policyDecisionReasons(summary) {
  return (summary ?? []).filter((r) => r.effect === "deny" || r.effect === "escalate");
}

// ============================================================================
// 渲染:风险刻度盘(三段)
//
// ★ 分数、阈值、因子、档位全部来自 turn.risk / pending.risk,由服务端组装。
//   前端不做"多少分算高风险"的判断 —— 刻度线画在哪由 thresholds 决定,
//   指针停在哪由 score 决定,这里只有「把给定区间按比例画出来」这一件事。
// ============================================================================

/** 档位枚举 → 人话与配色(与 LANE_TEXT 同类:翻译,不是判断) */
const RISK_TIER_TEXT = {
  auto: { label: "低风险", cls: "ok", note: "这类操作可以直接办理" },
  confirm: { label: "中风险", cls: "warn", note: "需要您确认后才会执行" },
  strong_auth: { label: "高风险", cls: "danger", note: "需要您本人完成验证后才会执行" },
  blocked: { label: "已拦截", cls: "danger", note: "这一步不能代办" },
};

function renderDecisionPanel(risk, policySummary) {
  const reasons = policyDecisionReasons(policySummary);
  const autoAt = Number(risk?.thresholds?.auto);
  const confirmAt = Number(risk?.thresholds?.confirm);
  const scaleOk =
    typeof risk?.score === "number" && Number.isFinite(autoAt) && Number.isFinite(confirmAt) && confirmAt > autoAt;
  const factors = Array.isArray(risk?.factors) ? risk.factors : [];
  // 没有评分(只读能力)时,条款仍要出得来 —— 例如这一步被直接拒绝
  if (!scaleOk && reasons.length === 0) return null;

  const box = document.createElement("div");
  box.className = "risk";

  if (scaleOk) {
    const score = Math.max(0, Math.min(100, risk.score));
    const tier = RISK_TIER_TEXT[risk.tier] ?? RISK_TIER_TEXT.confirm;
    box.classList.add(`risk-${tier.cls}`);

    const top = document.createElement("div");
    top.className = "risk-top";
    const name = document.createElement("span");
    name.className = "risk-name";
    name.innerHTML = '<i class="ri-speed-up-line" aria-hidden="true"></i>风险评分';
    const value = document.createElement("span");
    value.className = "risk-value";
    value.textContent = score.toFixed(1);
    const tag = document.createElement("span");
    tag.className = `risk-tag ${tier.cls}`;
    tag.textContent = tier.label;
    top.append(name, value, tag);
    box.appendChild(top);

    // 三段条:宽度完全由 thresholds 推出,阈值改了三段自然跟着变
    const bar = document.createElement("div");
    bar.className = "risk-bar";
    for (const [cls, width] of [
      ["ok", autoAt],
      ["warn", confirmAt - autoAt],
      ["danger", 100 - confirmAt],
    ]) {
      const seg = document.createElement("span");
      seg.className = `risk-seg ${cls}`;
      seg.style.width = `${width}%`;
      bar.appendChild(seg);
    }
    const needle = document.createElement("span");
    needle.className = "risk-needle";
    needle.style.left = `${score}%`;
    needle.setAttribute("aria-hidden", "true");
    bar.appendChild(needle);
    box.appendChild(bar);

    const scale = document.createElement("div");
    scale.className = "risk-scale";
    for (const m of [
      { at: 0, text: "0" },
      { at: autoAt, text: String(autoAt) },
      { at: confirmAt, text: String(confirmAt) },
      { at: 100, text: "100" },
    ]) {
      const s = document.createElement("span");
      s.style.left = `${m.at}%`;
      s.textContent = m.text;
      scale.appendChild(s);
    }
    box.appendChild(scale);

    const verdict = document.createElement("div");
    verdict.className = "risk-verdict";
    verdict.textContent = tier.note;
    box.appendChild(verdict);
  }

  /**
   * 展开区:这一分是怎么来的(因子)+ 命中了哪些条款(规则)。
   * 默认折叠 —— 第一层只给结论,第二层才给证据,ruleId 这类工程信息收在这里。
   */
  if (factors.length > 0 || reasons.length > 0) {
    const det = document.createElement("details");
    det.className = "risk-factors";
    const sum = document.createElement("summary");
    const parts = [];
    if (factors.length > 0) parts.push(`${factors.length} 项风险因子`);
    if (reasons.length > 0) parts.push(`${reasons.length} 条规则条款`);
    sum.textContent = `${scaleOk ? "为什么需要您介入" : "裁决依据"}(${parts.join(" · ")})`;
    det.appendChild(sum);

    if (factors.length > 0) {
      const list = document.createElement("div");
      list.className = "risk-factor-list";
      for (const f of factors) {
        const row = document.createElement("div");
        row.className = "risk-factor";
        const fn = document.createElement("span");
        fn.className = "risk-factor-name";
        fn.textContent = f.detail ? `${f.name}:${f.detail}` : String(f.name ?? "");
        const fc = document.createElement("span");
        const c = Number(f.contribution) || 0;
        fc.className = `risk-factor-c ${c > 0 ? "up" : c < 0 ? "down" : ""}`;
        fc.textContent = `${c > 0 ? "+" : ""}${c.toFixed(1)}`;
        row.append(fn, fc);
        list.appendChild(row);
      }
      det.appendChild(list);
    }

    if (reasons.length > 0) {
      const head = document.createElement("div");
      head.className = "risk-rules-head";
      head.textContent = "命中的规则条款";
      det.appendChild(head);
      const list = document.createElement("div");
      list.className = "risk-rules";
      for (const r of reasons) {
        const item = document.createElement("div");
        item.className = `risk-rule ${r.effect ?? ""}`;
        const rid = document.createElement("span");
        rid.className = "rid";
        rid.textContent = `[${r.ruleId}] `;
        item.append(rid, document.createTextNode(r.message ?? ""));
        list.appendChild(item);
      }
      det.appendChild(list);
    }

    // 口径说明放在最底层:是给人看的注释,不该占据标题
    const note = document.createElement("div");
    note.className = "risk-note";
    note.textContent = "以上分数与条款均由确定性规则引擎计算,无 LLM 参与;可在审计面板按 trace 逐条核对。";
    det.appendChild(note);
    box.appendChild(det);
  }

  return box;
}

// ============================================================================
// 渲染:办理流程(可视化步骤链路)
//
// ★ 这一块**只负责画**。每一步归谁办(Agent 自主 / 等你确认 / 需你验证 /
//   已转人工审批 / 已被拦截)由服务端在 flow.steps[].lane 上给出;
//   前端不做任何"这句话像不像转账""该不该拦"的判断 ——
//   否则界面与后端迟早会各说各话,而那是这类产品最难查的一类故障。
// ============================================================================

/** 步骤归属 → 人话(服务端给 lane,前端只做翻译,不做判断) */
const LANE_TEXT = {
  auto: "Agent 自主执行",
  customer: "等您确认",
  customer_auth: "需您本人验证",
  human_review: "已转人工审批",
  blocked: "已被拦截",
};

const STEP_ICON = [
  [/收到您的请求/, "ri-inbox-archive-line"],
  [/理解为您的意图/, "ri-question-answer-line"],
  [/拆成|执行计划/, "ri-node-tree"],
  [/策略校验/, "ri-shield-check-line"],
  [/冻结/, "ri-lock-2-line"],
  [/备好待确认内容/, "ri-file-list-3-line"],
  [/身份验证/, "ri-fingerprint-line"],
  [/已办结/, "ri-checkbox-circle-line"],
  [/执行失败|未通过/, "ri-close-circle-line"],
  [/人工审批/, "ri-user-follow-line"],
  [/申请已提交/, "ri-send-plane-line"],
  [/挂失/, "ri-alarm-warning-line"],
  [/风险|测评|确认书/, "ri-shield-star-line"],
  [/取消/, "ri-close-line"],
  [/拒绝|不能/, "ri-forbid-2-line"],
];

function stepIcon(label) {
  for (const [re, icon] of STEP_ICON) if (re.test(label)) return icon;
  return "ri-record-circle-line";
}

const STATUS_ICON = {
  done: "ri-check-line",
  active: "ri-loader-4-line",
  waiting: "ri-more-line",
  failed: "ri-close-line",
  skipped: "ri-subtract-line",
};

/** 单条流程步骤:圆点 + 连接线 + 人话 + 归属标签 */
function flowStepEl(step, last) {
  const row = document.createElement("div");
  row.className = `flow-step ${step.status}`;

  const rail = document.createElement("div");
  rail.className = "flow-rail";
  const dot = document.createElement("span");
  dot.className = `flow-dot ${step.status}`;
  const mark = document.createElement("i");
  mark.className = STATUS_ICON[step.status] ?? "ri-check-line";
  mark.setAttribute("aria-hidden", "true");
  dot.appendChild(mark);
  rail.appendChild(dot);
  if (!last) {
    const line = document.createElement("span");
    line.className = "flow-line";
    rail.appendChild(line);
  }
  row.appendChild(rail);

  const body = document.createElement("div");
  body.className = "flow-body";

  const head = document.createElement("div");
  head.className = "flow-label";
  const icon = document.createElement("i");
  icon.className = `${stepIcon(step.label)} flow-ico`;
  icon.setAttribute("aria-hidden", "true");
  head.append(icon, document.createTextNode(step.label));
  body.appendChild(head);

  if (step.detail) {
    const d = document.createElement("div");
    d.className = "flow-detail";
    d.textContent = step.detail;
    body.appendChild(d);
  }

  const lane = document.createElement("span");
  lane.className = `flow-lane l-${step.lane}`;
  lane.textContent = LANE_TEXT[step.lane] ?? step.lane;
  body.appendChild(lane);

  row.appendChild(body);
  return row;
}

/**
 * 办理流程卡片。
 *
 * ★ 默认展开还是折叠,由**这一步是否还需要客户动手**决定:
 *   还在等他确认/验证 → 展开(他需要知道下一步归谁);
 *   已经办结 → 折叠(结果已经在回复里说清楚了,想看细节再点开)。
 *   全部展开会让聊天记录很快被流程图淹没,全部折叠又等于没做这个功能。
 */
function renderFlow(flow, turn) {
  if (!flow) return null;
  const box = document.createElement("details");
  box.className = "flow-card";
  const pendingNow = Boolean(turn?.promptFor?.kind && turn.promptFor.kind !== "none");
  const canSaveFlow = Boolean(flow.saveable && flow.template);
  if (pendingNow || canSaveFlow) box.open = true;

  const head = document.createElement("summary");
  head.className = "flow-head";
  const title = document.createElement("span");
  title.className = "flow-title";
  const ico = document.createElement("i");
  ico.className = pendingNow ? "ri-loader-4-line flow-spin" : "ri-route-line";
  ico.setAttribute("aria-hidden", "true");
  title.append(ico, document.createTextNode(pendingNow ? `正在办理:${flow.title}` : flow.title));
  const badge = document.createElement("span");
  badge.className = `flow-badge ${flow.handedToHuman ? "human" : pendingNow ? "doing" : "done"}`;
  badge.textContent = flow.handedToHuman ? "待人工审批" : pendingNow ? "进行中" : "已办结";
  head.append(title, badge);
  box.appendChild(head);

  const steps = document.createElement("div");
  steps.className = "flow-steps";
  (flow.steps ?? []).forEach((s, i) => steps.appendChild(flowStepEl(s, i === flow.steps.length - 1)));
  box.appendChild(steps);

  const summary = document.createElement("div");
  summary.className = "flow-summary";
  summary.textContent = flow.summary ?? "";
  box.appendChild(summary);

  /**
   * ★ "保存为常用流程"按钮。
   *
   *   保存的是**服务端派生出来的意图模板**,不是界面上这段文字 ——
   *   前端只把 traceId 递回去,模板由服务端按同一条规则生成。
   *   (若让前端把模板内容拼好发上去,常用流程就成了一条绕过服务端的写入口。)
   */
  if (flow.saveable && flow.template) {
    const lead = document.createElement("div");
    lead.className = "flow-summary flow-save-lead";
    lead.textContent = "这笔可以存为常用流程,下次少打字 —— 保存后在左上角抽屉「我的常用流程」里。";
    box.appendChild(lead);

    const save = document.createElement("button");
    save.type = "button";
    save.className = "flow-save";
    const si = document.createElement("i");
    si.className = "ri-bookmark-line";
    si.setAttribute("aria-hidden", "true");
    save.append(si, document.createTextNode("存为常用流程"));
    save.addEventListener("click", async () => {
      save.disabled = true;
      save.textContent = "保存中…";
      try {
        // ★ 必须把 sessionId 一起带上:资金类操作跨两轮,
        //   "执行那一轮"的审计里没有确认卡,服务端要按会话把上一轮那张卡找回来。
        const r = await post("/api/flows/save", {
          traceId: turn?.traceId,
          customerId: profile?.customerId,
          sessionId,
        });
        save.className = "flow-save saved";
        save.textContent = "已存入常用服务";
        noteSaved(r.flow);
        void refreshDesk();
      } catch (err) {
        save.disabled = false;
        save.textContent = "存为常用流程";
        addMessage({ role: "agent", text: `没能保存常用流程:${err.message}`, variant: "notice" });
      }
    });
    box.appendChild(save);
  }

  return box;
}

/** 保存成功后的确认语 —— 必须说清**存在哪里**,否则客户根本找不到 */
function noteSaved(flow) {
  if (!flow) return;
  addMessage({
    role: "agent",
    text:
      `已保存为常用流程「${flow.name}」。它现在在**左上角抽屉 → 我的常用流程**里(以后每用一次,它会自动排到更前面)。` +
      `\n\n下次可以直接说「${flow.say ?? flow.name}」,也可以打开抽屉点那个入口。`,
    variant: "notice",
  });
}

// ============================================================================
// 渲染:数字与规则的出处(来源 / 主体 / 时效 / 计算过程)
// ============================================================================

function renderCitations(citations) {
  const items = citations ?? [];
  if (items.length === 0) return null;

  const details = document.createElement("details");
  details.className = "cite";
  const head = document.createElement("summary");
  const qi = document.createElement("i");
  qi.className = "ri-question-line";
  qi.setAttribute("aria-hidden", "true");
  head.append(qi, document.createTextNode(`这些数字和规则的出处(${items.length} 条)`));
  details.appendChild(head);

  const list = document.createElement("div");
  list.className = "cite-list";
  for (const c of items) {
    const item = document.createElement("div");
    item.className = `cite-item ${c.kind ?? "data"}`;

    const topic = document.createElement("div");
    topic.className = "cite-topic";
    topic.textContent = c.topic ?? "";
    item.appendChild(topic);

    const meta = document.createElement("div");
    meta.className = "cite-meta";
    meta.textContent = `来源:${c.source ?? "—"} · 主体:${c.subject ?? "—"} · 时效:${c.effective ?? "—"}`;
    item.appendChild(meta);

    if (Array.isArray(c.calculation) && c.calculation.length > 0) {
      const calc = document.createElement("div");
      calc.className = "cite-calc";
      for (const line of c.calculation) {
        const row = document.createElement("div");
        row.textContent = line;
        calc.appendChild(row);
      }
      item.appendChild(calc);
    }
    if (c.note) {
      const note = document.createElement("div");
      note.className = "cite-note";
      note.textContent = c.note;
      item.appendChild(note);
    }
    list.appendChild(item);
  }
  details.appendChild(list);
  return details;
}

// ============================================================================
// 渲染:个性化主动建议(点一下就能办)
// ============================================================================

function renderSuggestions(suggestions) {
  const all = suggestions ?? [];
  const planSteps = all
    .filter((s) => s.ruleId === "EVENT-PLAN-STEP" || s.ruleId === "BRIEF-NEXT-STEP")
    .slice(0, 3);
  const items = all.filter((s) => s.ruleId !== "EVENT-PLAN-STEP" && s.ruleId !== "BRIEF-NEXT-STEP").slice(0, 3);
  if (planSteps.length === 0 && items.length === 0) return null;

  const wrap = document.createElement("div");
  wrap.className = "suggest-wrap";

  if (planSteps.length > 0) {
    const plan = document.createElement("div");
    plan.className = "suggest suggest-plan";
    const planTitle = document.createElement("div");
    planTitle.className = "suggest-title";
    planTitle.textContent =
      planSteps[0]?.ruleId === "BRIEF-NEXT-STEP" ? "发薪清单 · 点这里继续" : "联动方案 · 点这里继续";
    plan.appendChild(planTitle);
    for (const s of planSteps) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "suggest-btn suggest-btn-plan";
      const ico = document.createElement("i");
      ico.className = "ri-route-line";
      ico.setAttribute("aria-hidden", "true");
      const text = document.createElement("span");
      text.className = "suggest-text";
      text.textContent = s.text;
      b.append(ico, text);
      b.addEventListener("click", () => submit(s.say));
      plan.appendChild(b);
    }
    wrap.appendChild(plan);
  }

  if (items.length === 0) return wrap;

  const inner = document.createElement("div");
  inner.className = "suggest";
  const title = document.createElement("div");
  title.className = "suggest-title";
  title.textContent = "接下来如果您愿意";
  inner.appendChild(title);

  for (const s of items) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "suggest-btn";
    const ico = document.createElement("i");
    ico.className = "ri-lightbulb-line";
    ico.setAttribute("aria-hidden", "true");
    const text = document.createElement("span");
    text.className = "suggest-text";
    text.textContent = s.text;
    b.append(ico, text);
    b.addEventListener("click", () => submit(s.say));
    inner.appendChild(b);

    /**
     * ★ 把"为什么现在提"也显示出来。
     *   主动建议最招人烦的地方就是"你凭什么猜我需要这个";
     *   把依据摊开(基于哪几笔、哪条规则),建议才像助手而不像广告。
     */
    if (s.reason) {
      const why = document.createElement("div");
      why.className = "suggest-why";
      why.textContent = `依据:${s.reason}`;
      inner.appendChild(why);
    }
  }
  wrap.appendChild(wrapStackFold(inner, `可选建议(${items.length})`));
  return wrap;
}

// ============================================================================
// 渲染:动作按钮
// ============================================================================

function renderActions(turn) {
  const kind = turn.promptFor?.kind;
  if (!kind || kind === "none" || kind === "clarify") return null;

  const box = document.createElement("div");
  box.className = "actions";

  if (kind === "confirm") {
    const ok = mkBtn("确认执行", "btn-primary", () => runAction({ kind: "confirm", refId: turn.promptFor.refId }, box));
    const no = mkBtn("取消", "btn-ghost", () => runAction({ kind: "cancel", refId: turn.promptFor.refId }, box));
    box.append(ok, no);
  } else if (kind === "strong_auth") {
    // ★ 真实的手机银行这里会弹出系统人脸识别。网页做不到,
    //   所以做成一个"模拟原生验证"的条 —— 但**回执仍然由服务端签发并验签**,
    //   前端拿不到密钥。这一点必须保住:否则演示就变成了"前端说了算"。
    const v = mkBtn("完成身份验证(模拟人脸)", "btn-primary", () => openAuthSheet(turn, box));
    const no = mkBtn("取消", "btn-ghost", () => runAction({ kind: "cancel", refId: turn.promptFor.refId }, box));
    box.append(v, no);
  }

  return box.children.length > 0 ? box : null;
}

/**
 * 把服务端"待确认动作"视图渲染成一张可操作的卡片。
 *
 * ★ 为什么需要这条路:一个未决的待确认动作会**挡住客户的下一个请求** ——
 *   系统会回一句「你还有一个操作在等你确认」并把它重述一遍。
 *   但如果界面只把这句话当纯文本显示,用户是**无法把它处理掉**的:
 *   他没有按钮可点,只能靠猜要回什么词。
 *   所以遇到"被挡住"的回复时,必须顺手把那张卡的摘要与按钮补上。
 */
function renderPendingCard(pending) {
  const box = document.createElement("div");
  box.className = "ui-card";

  const head = document.createElement("div");
  head.className = "ui-card-head";
  head.innerHTML = '<i class="ri-time-line" aria-hidden="true"></i>';
  head.appendChild(document.createTextNode("还有一个操作在等您处理"));
  box.appendChild(head);

  const body = document.createElement("div");
  body.className = "ui-card-body";

  const row = (label, value, emph) => {
    const r = document.createElement("div");
    r.className = `ui-row${emph ? " emph" : ""}`;
    const l = document.createElement("div");
    l.className = "ui-row-label";
    l.textContent = label;
    const v = document.createElement("div");
    v.className = "ui-row-value";
    v.textContent = value;
    r.append(l, v);
    return r;
  };

  body.appendChild(row("待办的这件事", pending.summary || "一项待确认的操作", true));
  if (pending.requiredTier === "strong_auth") {
    body.appendChild(row("需要", "先完成身份验证,再确认"));
  }
  // 冻结载荷里挑出用户看得懂的几项(全部来自服务端已剥离内部字段的视图)
  const fp = pending.frozenPayload ?? {};
  if (fp.payeeName) body.appendChild(row("收款人", String(fp.payeeName)));
  if (typeof fp.amount === "number") body.appendChild(row("金额", `¥${fp.amount.toLocaleString("zh-CN")}`));
  if (fp.memo) body.appendChild(row("备注", String(fp.memo)));
  if (fp.cardId) body.appendChild(row("涉及卡片", String(fp.cardId)));
  box.appendChild(body);

  // 同一张待办卡的第二帧(被悬空待办挡住时补画):风险刻度盘同样挂上
  const pendingRisk = renderDecisionPanel(pending.risk);
  if (pendingRisk) box.appendChild(pendingRisk);

  const warn = document.createElement("div");
  warn.className = "ui-card-warn";
  warn.textContent =
    "这张卡是您上一句话冻结下来的内容。为了不出现「以为办好了、其实没办」,请先把这一笔处理掉。";
  box.appendChild(warn);

  const actions = document.createElement("div");
  actions.className = "actions";
  actions.style.padding = "10px 13px";
  const isAuth = pending.requiredTier === "strong_auth";
  actions.append(
    mkBtn(isAuth ? "完成身份验证" : "确认执行", "btn-primary", () => {
      if (isAuth) openAuthSheet({ promptFor: { kind: "strong_auth", refId: pending.pendingId } }, actions);
      else runAction({ kind: "confirm", refId: pending.pendingId }, actions);
    }),
    mkBtn("取消", "btn-ghost", () => runAction({ kind: "cancel", refId: pending.pendingId }, actions)),
  );
  box.appendChild(actions);

  return box;
}

function mkBtn(label, cls, onClick) {
  const b = document.createElement("button");
  b.className = `btn ${cls}`;
  b.type = "button";
  b.textContent = label;
  b.addEventListener("click", onClick);
  return b;
}

async function runAction(action, box) {
  if (busy) return;
  if (box) for (const b of box.querySelectorAll("button")) b.disabled = true;
  busy = true;
  setThinking(true);
  try {
    const turn = await sendAction(action);
    renderTurn(turn);
    void refreshDesk();
    void refreshThreadTags();
  } catch (err) {
    addMessage({ role: "agent", text: `操作没有完成:${err.message}`, variant: "notice" });
  } finally {
    busy = false;
    setThinking(false);
  }
}

// ============================================================================
// 强验证弹层
// ============================================================================

/**
 * 强验证弹层。
 *
 * ★ 两个必须守住的点(实测被客户点出来的):
 *   ① **一按即失效** —— 点过"完成身份验证"之后,同一组按钮不能再点第二次。
 *      过去按钮只在"确认执行"这条路上被禁用,验证这条路没禁:客户连点两下,
 *      会开出两层弹层;验证通过后旧按钮还亮着,再点一次就变成"没有待确认的操作"。
 *      处理:打开弹层的同时禁用触发它的那组按钮;取消或验证前的失败再恢复。
 *   ② **签的必须是这一笔的载荷** —— 弹层只对 `refId` 指向的那条待办签发回执,
 *      不取"当前最新的一条"。否则先验证 A、中途又发起 B,再点 A 的按钮
 *      就会给 B 盖章(界面在办 A,服务端盖的是 B 的章)。
 */
function openAuthSheet(turn, box) {
  // 触发按钮立即禁用;成功办结后保持禁用,失败的中间步骤再恢复(见 release)
  const triggerButtons = box ? [...box.querySelectorAll("button")] : [];
  for (const b of triggerButtons) b.disabled = true;
  const release = () => {
    for (const b of triggerButtons) if (b.isConnected) b.disabled = false;
  };

  const refId = turn?.promptFor?.refId;
  const mask = document.createElement("div");
  mask.className = "sheet-mask";

  const sheet = document.createElement("div");
  sheet.className = "sheet";
  sheet.innerHTML = "";

  const face = document.createElement("div");
  face.className = "sheet-face";
  face.innerHTML = '<i class="ri-scan-face-line" aria-hidden="true"></i>';
  sheet.appendChild(face);

  const h = document.createElement("h3");
  h.textContent = "身份验证";
  sheet.appendChild(h);

  const p = document.createElement("p");
  p.textContent = "为完成这笔操作,需要验证您的身份。真机上这里会弹出系统人脸识别 / 指纹窗口。";
  sheet.appendChild(p);

  const btns = document.createElement("div");
  btns.className = "sheet-btns";

  /** 按 refId 取这一笔的载荷哈希;取不到说明已经办完或已过期 —— 不能再签任何东西 */
  const loadTarget = async () => {
    const q = new URLSearchParams({ customerId: profile?.customerId ?? "" });
    if (refId) q.set("refId", refId);
    const r = await get(`/api/demo/pending?${q.toString()}`);
    if (!r.pending) throw new Error("这笔操作已经处理过了(或已过期),不用再验证一次");
    return r.pending;
  };

  const pass = document.createElement("button");
  pass.className = "btn btn-primary";
  pass.type = "button";
  pass.textContent = "模拟验证通过";
  pass.addEventListener("click", async () => {
    pass.disabled = true;
    fail.disabled = true;
    cancel.disabled = true;
    pass.textContent = "验证中…";
    try {
      // ★ 三步,每一步都由服务端决定:
      //   ① 取**这一笔**的载荷哈希 → ② 请"安全环境"签发回执 → ③ 带着回执确认
      const target = await loadTarget();
      const p2 = await post("/api/demo/sign-auth-proof", {
        method: "biometric",
        payloadHash: target.payloadHash,
      });
      mask.remove();
      // 走到这里已经"执行过"了:按钮保持禁用,不再给第二次机会
      await runAction({ kind: "confirm", refId: target.pendingId, authProof: p2.proof }, null);
    } catch (err) {
      mask.remove();
      release();
      addMessage({ role: "agent", text: `验证没有完成:${err.message}`, variant: "notice" });
    }
  });

  const fail = document.createElement("button");
  fail.className = "btn btn-ghost";
  fail.type = "button";
  fail.textContent = "模拟验证失败(演示签名校验)";
  fail.addEventListener("click", async () => {
    pass.disabled = true;
    fail.disabled = true;
    cancel.disabled = true;
    try {
      const target = await loadTarget();
      const p2 = await post("/api/demo/sign-auth-proof", {
        method: "biometric",
        payloadHash: target.payloadHash,
      });
      // 篡改签名第一位 —— 服务端验签必须失败
      const bad = { ...p2.proof, signature: (p2.proof.signature[0] === "a" ? "b" : "a") + p2.proof.signature.slice(1) };
      mask.remove();
      await runAction({ kind: "confirm", refId: target.pendingId, authProof: bad }, null);
    } catch (err) {
      mask.remove();
      release();
      addMessage({ role: "agent", text: `验证没有完成:${err.message}`, variant: "notice" });
    }
  });

  const cancel = document.createElement("button");
  cancel.className = "btn btn-ghost";
  cancel.type = "button";
  cancel.textContent = "取消";
  cancel.addEventListener("click", () => {
    mask.remove();
    // 只是关掉弹层、没做任何验证 —— 按钮恢复,客户可以重新点
    release();
  });

  btns.append(pass, fail, cancel);
  sheet.appendChild(btns);

  const note = document.createElement("div");
  note.className = "sheet-note";
  note.textContent =
    "回执由服务端的可信环境签发并验签,前端拿不到密钥 —— 所以即使前端被改,也伪造不出验证。";
  sheet.appendChild(note);

  mask.appendChild(sheet);
  $("device").appendChild(mask);

  if (!turn) {
    mask.remove();
    release();
  }
}

// ============================================================================
// 渲染:可视块(材料比对 / 复核决策 / 误报撤回)
//
// ★ 这三块共同点是"关系比数值重要",所以用对照表 / 评分条 / 前后对照来画,
//   而不是把它们塞回一段话里。服务端只给结构与语义(冲突/一致、成本/风险),
//   配色与排版在这里 —— 与流程卡同一条边界:前端不做业务判断。
// ============================================================================

function visualChip(text, cls) {
  const s = document.createElement("span");
  s.className = `v-chip ${cls}`;
  s.textContent = text;
  return s;
}

/** 材料比对:列=材料,行=字段;矛盾行高亮,差异格加 ≠ */
function renderDocDiff(v) {
  const box = document.createElement("div");
  box.className = "visual doc-diff";

  const head = document.createElement("div");
  head.className = "v-head";
  const t = document.createElement("div");
  t.className = "v-title";
  t.textContent = v.title;
  head.appendChild(t);
  head.appendChild(
    visualChip(v.conflictCount > 0 ? `${v.conflictCount} 处矛盾` : "关键信息一致", v.conflictCount > 0 ? "bad" : "ok"),
  );
  box.appendChild(head);

  const verdict = document.createElement("div");
  verdict.className = `v-verdict ${v.conflictCount > 0 ? "warn" : "ok"}`;
  verdict.textContent = v.verdict;
  box.appendChild(verdict);

  const table = document.createElement("div");
  table.className = "dd-table";
  table.style.setProperty("--cols", String(v.documents.length));

  // 表头:空 + 每份材料的种类标签
  const header = document.createElement("div");
  header.className = "dd-row dd-header";
  const corner = document.createElement("div");
  corner.className = "dd-label";
  corner.textContent = "字段";
  header.appendChild(corner);
  for (const d of v.documents) {
    const c = document.createElement("div");
    c.className = "dd-cell dd-doc";
    const k = document.createElement("div");
    k.className = "dd-doc-kind";
    k.textContent = d.kindLabel;
    const n = document.createElement("div");
    n.className = "dd-doc-name";
    n.textContent = d.label;
    c.append(k, n);
    header.appendChild(c);
  }
  table.appendChild(header);

  for (const row of v.rows ?? []) {
    const r = document.createElement("div");
    r.className = `dd-row dd-${row.severity}`;
    const label = document.createElement("div");
    label.className = "dd-label";
    label.textContent = row.label;
    r.appendChild(label);
    for (const cell of row.values ?? []) {
      const c = document.createElement("div");
      c.className = `dd-cell${cell.differs ? " dd-diff" : ""}`;
      c.textContent = cell.text;
      if (cell.differs) {
        const mark = document.createElement("span");
        mark.className = "dd-mark";
        mark.textContent = "≠";
        mark.setAttribute("aria-label", "与其它材料不一致");
        c.appendChild(mark);
      }
      r.appendChild(c);
    }
    if (row.note && row.severity !== "ok") {
      const note = document.createElement("div");
      note.className = "dd-note";
      note.textContent = row.note;
      r.appendChild(note);
    }
    table.appendChild(r);
  }
  box.appendChild(table);

  if (Array.isArray(v.actions) && v.actions.length > 0) {
    box.appendChild(visualActions(v.actions));
  }
  return box;
}

/** 复核决策:两条评分 + 结论 + 缺口 */
function renderReviewPlan(v) {
  const box = document.createElement("div");
  box.className = "visual review-plan";

  const head = document.createElement("div");
  head.className = "v-head";
  const t = document.createElement("div");
  t.className = "v-title";
  t.textContent = v.title;
  head.appendChild(t);
  head.appendChild(visualChip(v.decisionLabel, v.decision === "inspect_gaps" ? "ok" : "info"));
  box.appendChild(head);

  const bars = document.createElement("div");
  bars.className = "rp-bars";
  for (const [label, score, hint] of [
    ["重扫成本", v.rescanCost.score, "再算一遍要花多少功夫"],
    ["遗漏风险", v.omissionRisk.score, "上次没看到的部分有多重要"],
  ]) {
    const row = document.createElement("div");
    row.className = "rp-bar-row";
    const l = document.createElement("div");
    l.className = "rp-bar-label";
    l.textContent = label;
    const track = document.createElement("div");
    track.className = "rp-track";
    const fill = document.createElement("div");
    const cls = label === "遗漏风险" ? (score >= 60 ? "risk-high" : score >= 30 ? "risk-mid" : "risk-low") : "cost";
    fill.className = `rp-fill ${cls}`;
    fill.style.width = `${Math.max(3, Math.min(100, score))}%`;
    track.appendChild(fill);
    const num = document.createElement("div");
    num.className = "rp-bar-num";
    num.textContent = String(score);
    num.title = hint;
    row.append(l, track, num);
    bars.appendChild(row);
  }
  box.appendChild(bars);

  const details = document.createElement("details");
  details.className = "rp-why";
  const sm = document.createElement("summary");
  sm.textContent = "这两项是怎么算的";
  details.appendChild(sm);
  for (const f of [...(v.rescanCost.factors ?? []), ...(v.omissionRisk.factors ?? [])]) {
    const line = document.createElement("div");
    line.className = "rp-factor";
    line.textContent = f;
    details.appendChild(line);
  }
  box.appendChild(details);

  if (Array.isArray(v.gaps) && v.gaps.length > 0) {
    const g = document.createElement("div");
    g.className = "rp-gaps";
    for (const gap of v.gaps) {
      const line = document.createElement("div");
      line.className = "rp-gap";
      line.textContent = `· ${gap}`;
      g.appendChild(line);
    }
    box.appendChild(g);
  }

  if (Array.isArray(v.actions) && v.actions.length > 0) {
    box.appendChild(visualActions(v.actions));
  }
  return box;
}

/** 误报撤回:证据 → 撤回 → 仍需复核 */
function renderRetraction(v) {
  const box = document.createElement("div");
  box.className = "visual retraction";

  const head = document.createElement("div");
  head.className = "v-head";
  const t = document.createElement("div");
  t.className = "v-title";
  t.textContent = v.title;
  head.appendChild(t);
  head.appendChild(visualChip(`撤回 ${v.withdrawn.length} 条`, "ok"));
  box.appendChild(head);

  const ev = document.createElement("div");
  ev.className = "rt-evidence";
  const evLabel = document.createElement("div");
  evLabel.className = "rt-evidence-label";
  evLabel.textContent = "依据您的补充说明";
  const evText = document.createElement("div");
  evText.className = "rt-evidence-text";
  evText.textContent = v.evidence;
  ev.append(evLabel, evText);
  box.appendChild(ev);

  for (const w of v.withdrawn ?? []) {
    const item = document.createElement("div");
    item.className = "rt-item rt-withdrawn";
    const mark = document.createElement("span");
    mark.className = "rt-mark";
    mark.textContent = "已撤回";
    const body = document.createElement("div");
    const title = document.createElement("div");
    title.className = "rt-title";
    title.textContent = w.title;
    const reason = document.createElement("div");
    reason.className = "rt-reason";
    reason.textContent = `原判定依据:${w.reason}`;
    body.append(title, reason);
    item.append(mark, body);
    box.appendChild(item);
  }

  if ((v.stillOpen ?? []).length > 0) {
    const sub = document.createElement("div");
    sub.className = "rt-sub";
    sub.textContent = `仍需您复核(${v.stillOpen.length})`;
    box.appendChild(sub);
    for (const s of v.stillOpen) {
      const item = document.createElement("div");
      item.className = "rt-item rt-open";
      const mark = document.createElement("span");
      mark.className = "rt-mark";
      mark.textContent = s.severity === "high" ? "高" : s.severity === "medium" ? "中" : "低";
      const body = document.createElement("div");
      const title = document.createElement("div");
      title.className = "rt-title";
      title.textContent = s.title;
      const reason = document.createElement("div");
      reason.className = "rt-reason";
      reason.textContent = s.reason;
      body.append(title, reason);
      item.append(mark, body);
      box.appendChild(item);
    }
  } else {
    const done = document.createElement("div");
    done.className = "rt-sub";
    done.textContent = "清单里没有其它待复核的异常了。";
    box.appendChild(done);
  }

  if (Array.isArray(v.actions) && v.actions.length > 0) {
    box.appendChild(visualActions(v.actions));
  }
  return box;
}

/** 可视块底部的动作按钮(点了就是发一句话,不是隐藏逻辑) */
function visualActions(actions) {
  const bar = document.createElement("div");
  bar.className = "v-actions";
  for (const a of actions) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "v-action";
    b.textContent = a.label;
    b.addEventListener("click", () => submit(a.say));
    bar.appendChild(b);
  }
  return bar;
}

function yuanLabel(n) {
  const value = Number(n);
  if (!Number.isFinite(value)) return "—";
  return `¥${value.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function chartRows(panel) {
  const rows = document.createElement("div");
  rows.className = "chart-rows";
  const peak = Math.max(
    1,
    ...panel.series.flatMap((point) => [Number(point.value) || 0, Number(point.value2) || 0]),
  );
  for (const point of panel.series) {
    const row = document.createElement("div");
    row.className = "chart-row";
    const name = document.createElement("div");
    name.className = "chart-name";
    name.textContent = point.label;
    row.appendChild(name);
    const tracks = document.createElement("div");
    tracks.className = "chart-tracks";
    const addBar = (amount, cls) => {
      const track = document.createElement("div");
      track.className = "chart-track";
      const bar = document.createElement("span");
      bar.className = `chart-bar ${cls}`;
      bar.style.width = `${Math.max(2, (Math.max(0, Number(amount) || 0) / peak) * 100)}%`;
      const num = document.createElement("span");
      num.className = "chart-num";
      num.textContent = yuanLabel(amount);
      track.append(bar, num);
      tracks.appendChild(track);
    };
    addBar(point.value, "inflow");
    if (panel.chart === "grouped") addBar(point.value2 ?? 0, "out");
    row.appendChild(tracks);
    rows.appendChild(row);
  }
  return rows;
}

function wrapCanvasText(g, text, x, y, maxWidth, lineHeight) {
  let line = "";
  for (const ch of text) {
    const trial = line + ch;
    if (g.measureText(trial).width > maxWidth && line) {
      g.fillText(line, x, y);
      y += lineHeight;
      line = ch;
    } else {
      line = trial;
    }
  }
  if (line) {
    g.fillText(line, x, y);
    y += lineHeight;
  }
  return y;
}

/** 把柱和数据说明画进同一张 PNG。数字只用服务端给的 value,不再计算。 */
function downloadBillChart(v) {
  const width = 960;
  const pad = 40;
  const font = "'Microsoft YaHei', 'PingFang SC', sans-serif";
  const measure = document.createElement("canvas").getContext("2d");
  measure.font = `13px ${font}`;
  let height = 92;
  for (const panel of v.panels) {
    height += 28;
    for (const point of panel.series) {
      height += panel.chart === "grouped" ? 46 : 28;
    }
    height += 12;
  }
  height += 36;
  for (const note of v.notes) {
    const wide = measure.measureText(note).width;
    height += Math.ceil(wide / (width - pad * 2)) * 22 + 6;
  }
  height += 36;

  const canvas = document.createElement("canvas");
  const ratio = 2;
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const g = canvas.getContext("2d");
  g.scale(ratio, ratio);
  g.fillStyle = "#ffffff";
  g.fillRect(0, 0, width, height);
  g.fillStyle = "#142033";
  g.font = `700 22px ${font}`;
  g.fillText(v.title, pad, 42);
  g.font = `13px ${font}`;
  g.fillStyle = "#5c6b80";
  wrapCanvasText(g, v.subtitle, pad, 68, width - pad * 2, 20);

  let y = 96;
  for (const panel of v.panels) {
    g.fillStyle = "#142033";
    g.font = `600 15px ${font}`;
    g.fillText(panel.title, pad, y);
    if (panel.chart === "grouped") {
      g.font = `12px ${font}`;
      g.fillStyle = "#1d4ed8";
      g.fillText(panel.legend[0] ?? "收入", width - 180, y);
      g.fillStyle = "#cf3a2b";
      g.fillText(panel.legend[1] ?? "支出", width - 110, y);
    }
    y += 18;
    const peak = Math.max(1, ...panel.series.flatMap((point) => [Number(point.value) || 0, Number(point.value2) || 0]));
    const labelWidth = 168;
    const barMax = width - pad * 2 - labelWidth - 110;
    for (const point of panel.series) {
      const draw = (amount, color, offset) => {
        g.fillStyle = "#142033";
        g.font = `13px ${font}`;
        if (offset === 0) g.fillText(point.label, pad, y + 12);
        const w = (Math.max(0, Number(amount) || 0) / peak) * barMax;
        g.fillStyle = color;
        g.fillRect(pad + labelWidth, y + offset, Math.max(w, 2), 10);
        g.fillStyle = "#5c6b80";
        g.fillText(yuanLabel(amount), pad + labelWidth + w + 8, y + offset + 10);
      };
      draw(point.value, "#1d4ed8", 0);
      if (panel.chart === "grouped") {
        draw(point.value2 ?? 0, "#cf3a2b", 16);
        y += 46;
      } else {
        y += 28;
      }
    }
    y += 8;
  }

  g.fillStyle = "#142033";
  g.font = `600 15px ${font}`;
  g.fillText("数据说明", pad, y + 8);
  y += 30;
  g.font = `13px ${font}`;
  g.fillStyle = "#334155";
  for (const note of v.notes) {
    y = wrapCanvasText(g, note, pad, y, width - pad * 2, 22);
    y += 4;
  }
  g.fillStyle = "#8b98ab";
  g.font = `12px ${font}`;
  g.fillText("说明与柱使用同一份账单结果,模型未改写金额。", pad, Math.min(y + 8, height - 18));

  const link = document.createElement("a");
  link.href = canvas.toDataURL("image/png");
  link.download = v.filename || "账单图表.png";
  link.click();
}

function renderBillChart(v) {
  const box = document.createElement("div");
  box.className = "visual bill-chart";

  const head = document.createElement("div");
  head.className = "v-head";
  const title = document.createElement("div");
  title.className = "v-title";
  title.textContent = v.title;
  head.appendChild(title);
  const save = document.createElement("button");
  save.type = "button";
  save.className = "v-action";
  save.textContent = "下载图表与说明";
  save.addEventListener("click", () => downloadBillChart(v));
  head.appendChild(save);
  box.appendChild(head);

  const sub = document.createElement("div");
  sub.className = "chart-sub";
  sub.textContent = v.subtitle;
  box.appendChild(sub);

  for (const panel of v.panels ?? []) {
    const block = document.createElement("div");
    block.className = "chart-panel";
    const name = document.createElement("div");
    name.className = "chart-panel-title";
    name.textContent = panel.title;
    block.appendChild(name);
    if (panel.chart === "grouped") {
      const legend = document.createElement("div");
      legend.className = "chart-legend";
      const a = document.createElement("span");
      a.className = "lg inflow";
      a.textContent = panel.legend?.[0] ?? "收入";
      const b = document.createElement("span");
      b.className = "lg out";
      b.textContent = panel.legend?.[1] ?? "支出";
      legend.append(a, b);
      block.appendChild(legend);
    }
    block.appendChild(chartRows(panel));
    box.appendChild(block);
  }

  if ((v.notes ?? []).length > 0) {
    const notes = document.createElement("div");
    notes.className = "chart-notes";
    for (const note of v.notes) {
      const line = document.createElement("p");
      line.textContent = note;
      notes.appendChild(line);
    }
    box.appendChild(wrapStackFold(notes, "数据说明"));
  }
  return box;
}

function renderVisual(visual) {
  if (!visual) return null;
  if (visual.kind === "doc_diff") return renderDocDiff(visual);
  if (visual.kind === "review_plan") return renderReviewPlan(visual);
  if (visual.kind === "retraction") return renderRetraction(visual);
  if (visual.kind === "bill_chart") return renderBillChart(visual);
  if (visual.kind === "anomaly_report") return renderAnomalyReport(visual);
  if (visual.kind === "list_report") return renderListReport(visual);
  if (visual.kind === "quiz_step") return renderQuizStep(visual);
  return null;
}

/**
 * 通用清单卡:余额、流水、定期支出、定时任务、AA 记录、卡列表共用这一套。
 * 前端只做排版与着色 —— 条目标题、数值、徽章、色调全部由能力侧给好。
 */
const LIST_REPORT_BADGE = {
  auto: "只读",
  confirm: "待确认",
  strong_auth: "强验证",
};
const LIST_REPORT_TONE = {
  auto: "ok",
  confirm: "medium",
  strong_auth: "high",
};

function listReportItemTone(it) {
  if (["high", "medium", "low", "ok"].includes(it.tone)) return it.tone;
  return LIST_REPORT_TONE[it.badge] ?? "plain";
}

function listReportItemBadge(it) {
  return LIST_REPORT_BADGE[it.badge] ?? it.badge ?? "";
}

function renderListReport(v) {
  const items = Array.isArray(v.items) ? v.items : [];
  const box = document.createElement("div");
  box.className =
    v.title === "联动方案" || v.title === "发薪分配清单" ? "lr lr-event-plan visual" : "lr";

  const head = document.createElement("div");
  head.className = "lr-head";
  head.innerHTML = '<i class="ri-list-check-3" aria-hidden="true"></i>';
  head.appendChild(document.createTextNode(v.title ?? "明细"));
  box.appendChild(head);

  if (v.subtitle) {
    const sub = document.createElement("div");
    sub.className = "lr-sub";
    sub.textContent = v.subtitle;
    box.appendChild(sub);
  }
  if (v.summary) {
    const sum = document.createElement("div");
    sum.className = "lr-summary";
    sum.textContent = v.summary;
    box.appendChild(sum);
  }

  if (v.bars?.length) {
    const chart = document.createElement("div");
    chart.className = "lr-bars";
    chart.appendChild(
      chartRows({
        title: "构成",
        chart: "bars",
        legend: ["金额"],
        series: v.bars.map((b) => ({ label: b.label, value: b.value })),
      }),
    );
    box.appendChild(chart);
  }

  const list = document.createElement("div");
  list.className = "lr-list";
  const visibleCap = 4;
  const primaryItems = items.length > visibleCap ? items.slice(0, visibleCap) : items;
  const extraItems = items.length > visibleCap ? items.slice(visibleCap) : [];
  for (const it of primaryItems) {
    const tone = listReportItemTone(it);
    const row = document.createElement("div");
    row.className = `lr-item ${tone}`;

    const top = document.createElement("div");
    top.className = "lr-item-top";
    const title = document.createElement("span");
    title.className = "lr-title";
    title.textContent = it.title ?? "";
    top.appendChild(title);
    const badgeText = listReportItemBadge(it);
    if (badgeText) {
      const b = document.createElement("span");
      b.className = `lr-badge ${tone}`;
      b.textContent = badgeText;
      top.appendChild(b);
    }
    if (it.value) {
      const val = document.createElement("span");
      val.className = "lr-value";
      val.textContent = it.value;
      top.appendChild(val);
    }
    row.appendChild(top);

    for (const line of it.lines ?? []) {
      const d = document.createElement("div");
      d.className = "lr-line";
      d.textContent = line;
      row.appendChild(d);
    }
    list.appendChild(row);
  }
  box.appendChild(list);

  if (extraItems.length > 0) {
    const moreList = document.createElement("div");
    moreList.className = "lr-list lr-list-more";
    for (const it of extraItems) {
      const tone = listReportItemTone(it);
      const row = document.createElement("div");
      row.className = `lr-item ${tone}`;
      const top = document.createElement("div");
      top.className = "lr-item-top";
      const title = document.createElement("span");
      title.className = "lr-title";
      title.textContent = it.title ?? "";
      top.appendChild(title);
      const badgeText = listReportItemBadge(it);
      if (badgeText) {
        const b = document.createElement("span");
        b.className = `lr-badge ${tone}`;
        b.textContent = badgeText;
        top.appendChild(b);
      }
      if (it.value) {
        const val = document.createElement("span");
        val.className = "lr-value";
        val.textContent = it.value;
        top.appendChild(val);
      }
      row.appendChild(top);
      for (const line of it.lines ?? []) {
        const d = document.createElement("div");
        d.className = "lr-line";
        d.textContent = line;
        row.appendChild(d);
      }
      moreList.appendChild(row);
    }
    box.appendChild(wrapStackFold(moreList, `其余 ${extraItems.length} 条明细`));
  }

  if (v.footer) {
    const f = document.createElement("div");
    f.className = "lr-footer";
    f.textContent = v.footer;
    box.appendChild(wrapStackFold(f, "口径与提示"));
  }
  if (v.actions?.length) {
    const actWrap = document.createElement("div");
    actWrap.className = "lr-actions-head";
    actWrap.textContent = "下一步(点选即发送)";
    box.appendChild(actWrap);
    box.appendChild(visualActions(v.actions));
  }
  return box;
}

function renderQuizStep(v) {
  const box = document.createElement("div");
  box.className = "visual quiz-step";

  const head = document.createElement("div");
  head.className = "v-head";
  const title = document.createElement("div");
  title.className = "v-title";
  title.textContent = v.title ?? "问卷";
  head.appendChild(title);
  const prog = document.createElement("span");
  prog.className = "quiz-progress";
  prog.textContent = v.progress ?? "";
  head.appendChild(prog);
  box.appendChild(head);

  const q = document.createElement("div");
  q.className = "quiz-question";
  q.textContent = v.question ?? "";
  box.appendChild(q);

  const opts = document.createElement("div");
  opts.className = "quiz-options";
  for (const o of v.options ?? []) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "quiz-opt";
    b.textContent = o.label;
    b.addEventListener("click", () => submit(o.say ?? o.optionId));
    opts.appendChild(b);
  }
  box.appendChild(opts);
  return box;
}

/**
 * 异常交易清单卡:等级着色 + 依据 + 建议。
 * 等级是检测能力给的 severity,这里只做「等级 → 颜色/图标」的展示映射。
 */
function renderAnomalyReport(v) {
  const LEVEL = {
    high: { cls: "high", label: "高", icon: "ri-error-warning-line" },
    medium: { cls: "medium", label: "中", icon: "ri-alert-line" },
    low: { cls: "low", label: "低", icon: "ri-information-line" },
  };
  const items = Array.isArray(v.items) ? v.items : [];
  const box = document.createElement("div");
  box.className = "anom";

  const head = document.createElement("div");
  head.className = "anom-head";
  head.innerHTML = '<i class="ri-search-eye-line" aria-hidden="true"></i>异常交易检查';
  box.appendChild(head);

  const meta = document.createElement("div");
  meta.className = "anom-meta";
  meta.textContent = `${v.windowLabel ?? ""} · 检查了 ${v.checkedCount ?? 0} 笔支出`;
  box.appendChild(meta);

  if (v.summary) {
    const sum = document.createElement("div");
    sum.className = "anom-summary";
    sum.textContent = v.summary;
    box.appendChild(sum);
  }

  const list = document.createElement("div");
  list.className = "anom-list";
  for (const it of items) {
    const lv = LEVEL[it.severity] ?? LEVEL.low;
    const row = document.createElement("div");
    row.className = `anom-item ${lv.cls}`;

    const top = document.createElement("div");
    top.className = "anom-item-top";
    const badge = document.createElement("span");
    badge.className = `anom-badge ${lv.cls}`;
    badge.innerHTML = `<i class="${lv.icon}" aria-hidden="true"></i>${lv.label}`;
    const title = document.createElement("span");
    title.className = "anom-title";
    title.textContent = it.title ?? "";
    const date = document.createElement("span");
    date.className = "anom-date";
    date.textContent = it.dateLabel ?? "";
    top.append(badge, title, date);
    row.appendChild(top);

    if (it.description) {
      const d = document.createElement("div");
      d.className = "anom-desc";
      d.textContent = it.description;
      row.appendChild(d);
    }
    if (it.advice) {
      const a = document.createElement("div");
      a.className = "anom-advice";
      a.innerHTML = '<i class="ri-lightbulb-line" aria-hidden="true"></i>';
      a.appendChild(document.createTextNode(it.advice));
      row.appendChild(a);
    }
    list.appendChild(row);
  }
  box.appendChild(list);
  return box;
}

// ============================================================================
// 回合渲染
// ============================================================================

/**
 * ★ 业务线程 → 流程卡 DOM 的映射。
 *
 *   资金类操作跨两轮(先"等你确认"、再"已办结")。若每轮都新画一张卡,
 *   客户会看到上面一张永远停在"进行中",下面又冒出一张"已办结" ——
 *   实测被点名的就是这个:"我按确认后成功办理了,你的流程图没有更新,还依旧是进行中"。
 *
 *   所以同一 threadId 只保留**一张**卡:新一轮到达时把旧卡换掉、
 *   新卡插到最新那条回复下面(于是它"每次办理都在",且状态跟着事实走)。
 */
const flowCards = new Map();

/**
 * 从回复文本里折掉"卡片正文"。
 *
 * 服务端会把确认卡的每个字段同时写进文本(审计与文字渠道需要完整的一份),
 * 而界面上已经渲染了结构化卡片。若原样显示,客户会在一屏里看到两张一样的卡。
 * 所以在展示层把 `【标题】…` 那一段折掉 —— 证据链不动,只改呈现。
 */
function stripCardBlock(text, card) {
  const raw = String(text ?? "");
  const title = card?.title;
  if (!title) return raw;
  const marker = `【${title}】`;
  const idx = raw.indexOf(marker);
  if (idx < 0) return raw;

  const head = raw.slice(0, idx);
  const tail = raw.slice(idx).split("\n");
  // 标题行之后,凡是"字段行 / 空行 / 分隔线 / 可撤销 / 请注意"都属于这张卡
  const isCardLine = (l) => {
    const t = l.trim();
    if (t === "") return true;
    if (/^─+$/.test(t)) return true;
    if (/^(可撤销|请注意|⚠️)/.test(t)) return true;
    return /^[^:：\n]{1,14}[:：]/.test(t);
  };
  let i = 1;
  while (i < tail.length && isCardLine(tail[i])) i += 1;
  return `${head}${tail.slice(i).join("\n")}`.replace(/\n{3,}/g, "\n\n").trim();
}

function renderTurn(turn) {
  const card = renderCard(turn.card);
  const actions = renderActions(turn);
  const cites = renderCitations(turn.citations);
  const suggests = renderSuggestions(turn.suggestions);
  const visual = renderVisual(turn.visual);
  // 裁决解释只有一个入口:分数、因子、命中条款都在这一块里
  let decision = renderDecisionPanel(turn.risk, turn.policySummary);
  const fraud = renderFraudNotice(turn.fraud);

  const needsInteraction =
    turn.promptFor?.kind === "confirm" ||
    turn.promptFor?.kind === "strong_auth" ||
    Boolean(card) ||
    Boolean(actions);

  if (decision && !needsInteraction) {
    decision = wrapStackFold(decision, "风控与规则说明");
  }

  // 先处理流程卡:同一线程的旧卡要原地退役(避免聊天记录里堆一串"进行中")
  let flow = null;
  if (turn.flow) {
    flow = renderFlow(turn.flow, turn);
    const threadId = turn.flow.threadId ?? turn.flow.flowKey;
    const previous = flowCards.get(threadId);
    if (previous) {
      previous.remove();
      // 同一件事的第二次渲染:闪一下,让客户注意到状态变了。
      // 不强制展开 —— 办结后链路细节不该再占屏幕,想看再点开。
      flow.classList.add("is-update");
    }
    flowCards.set(threadId, flow);
  }

  // 有结构化卡片时:文本与卡片放进同一个"堆栈",视觉上属于同一条回复
  if (card || decision || fraud || actions || flow || cites || suggests || visual) {
    const stack = document.createElement("div");
    stack.className = "stack";
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    bubble.appendChild(renderText(stripCardBlock(turn.reply, turn.card)));
    stack.appendChild(bubble);
    // 可视块紧跟结论:它是这一轮最重要的信息
    if (visual) stack.appendChild(visual);
    if (card) stack.appendChild(card);
    // 防骗警示紧跟交易信息、先于任何按钮:客户必须在点确认之前看到它
    if (fraud) stack.appendChild(fraud);
    // 裁决解释放在「看什么」与「点哪里」之间:先知道这笔有多大风险,再决定按不按确认
    if (decision) stack.appendChild(decision);
    if (actions) stack.appendChild(actions);
    /**
     * ★ 顺序有意为之:先看他能做什么(卡片/按钮),再看他走到哪了(流程),
     *   最后才是"凭什么信这些数字"(出处)与"还能做什么"(建议)。
     *   把流程提到按钮之前,会让需要确认的那一步被推到屏幕下方 ——
     *   客户的第一反应是"我要点哪里",而不是"你经历了什么"。
     */
    if (flow) stack.appendChild(flow);
    if (cites) stack.appendChild(cites);
    if (suggests) stack.appendChild(suggests);
    addMessage({ role: "agent", stack });
  } else {
    const variant = turn.terminal?.kind === "denied" ? "denied" : undefined;
    const wrap = addMessage({ role: "agent", text: stripCardBlock(turn.reply, turn.card), variant });
    if (fraud) wrap.appendChild(fraud);
    if (decision) wrap.appendChild(decision);
  }

  pending = turn.promptFor?.kind && turn.promptFor.kind !== "none" ? turn.promptFor : null;

  // ★ 被"悬空待确认动作"挡住时,把那张卡补出来。
  //
  //   系统会回一句「你还有一个操作在等确认」并把它重述一遍 ——
  //   但如果界面只把它当纯文本显示,用户是**没办法把它处理掉**的:
  //   他没有按钮可点,只能靠猜要回什么词。所以这里顺手把可操作的卡补上。
  if (/还有一个操作在等/.test(turn.reply ?? "")) {
    void appendPendingCard();
  }

  return turn;
}

/** 拉取当前待确认动作并渲染成可操作卡片 */
async function appendPendingCard() {
  try {
    const p = (await get(`/api/demo/pending?sessionId=${encodeURIComponent(sessionId)}`)).pending;
    if (!p || (p.sessionId && p.sessionId !== sessionId)) return;
    const card = renderPendingCard(p);
    const wrap = document.createElement("div");
    wrap.className = "msg agent";
    const av = document.createElement("div");
    av.className = "avatar";
    av.innerHTML = '<i class="ri-robot-2-line" aria-hidden="true"></i>';
    const stack = document.createElement("div");
    stack.className = "stack";
    stack.appendChild(card);
    wrap.append(av, stack);
    messagesEl.appendChild(wrap);
    makeCollapsible(wrap);
    scrollMsgToStart(wrap);
  } catch {
    // 拉不到就算了 —— 这只是体验补强,不该反过来打断主流程
  }
}

function setThinking(on) {
  let el = document.getElementById("thinking");
  if (on && !el) {
    el = document.createElement("div");
    el.id = "thinking";
    el.className = "msg agent";
    el.innerHTML =
      '<div class="avatar"><i class="ri-robot-2-line" aria-hidden="true"></i></div>' +
      '<div class="bubble"><div class="typing"><i></i><i></i><i></i></div></div>';
    messagesEl.appendChild(el);
    scrollMsgToStart(el);
  } else if (!on && el) {
    el.remove();
  }
  sendBtn.disabled = on;
}

function scrollToEnd() {
  requestAnimationFrame(() => {
    paneChat.scrollTop = paneChat.scrollHeight;
  });
}

/** 把新消息顶对齐到聊天区顶部附近,方便从回复开头往下读(不强制滚到底) */
function scrollMsgToStart(wrap) {
  const pane = paneChat;
  if (!wrap || !pane) return;
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const paneTop = pane.getBoundingClientRect().top;
      const elTop = wrap.getBoundingClientRect().top;
      pane.scrollTop += elTop - paneTop - 8;
    });
  });
}

function wrapStackFold(node, label) {
  if (!node) return null;
  const det = document.createElement("details");
  det.className = "stack-fold";
  const sum = document.createElement("summary");
  sum.textContent = label;
  det.append(sum, node);
  return det;
}

// ============================================================================
// 提交
// ============================================================================

async function submit(text) {
  const value = String(text ?? "").trim();
  if (!value || busy) return;
  busy = true;
  setThinking(true);
  addMessage({ role: "user", text: value });
  inputEl.value = "";
  try {
    const turn = await sendText(value);
    renderTurn(turn);
    void refreshDesk();
    void refreshThreadTags();
  } catch (err) {
    addMessage({ role: "agent", text: `没能完成:${err.message}`, variant: "notice" });
  } finally {
    busy = false;
    setThinking(false);
    inputEl.focus();
  }
}

formEl.addEventListener("submit", (e) => {
  e.preventDefault();
  submit(inputEl.value);
});

// 移动端键盘弹起时,把输入框上方最近一条消息顶对齐,避免整页被顶到最底
inputEl.addEventListener("focus", () => {
  setTimeout(() => {
    const last = messagesEl.querySelector(".msg:last-of-type");
    if (last) scrollMsgToStart(last);
  }, 260);
});

// ============================================================================
// 首页引导(空会话时)
//
// ★ 布局:对话区只放一条轻量问候;常用服务 / 我的常用流程 / 我的卡片 /
//   账户概览 / 主动建议全部收进左上角抽屉。空会话时界面只剩"一句话 + 输入框",
//   需要入口时再滑出抽屉 —— 这是"整体简洁"的主要来源。
// ============================================================================

const QUICK = [
  { icon: "ri-exchange-funds-line", label: "转账汇款", text: "给老妈转500,备注买菜" },
  { icon: "ri-bar-chart-2-line", label: "账单分析", text: "上个月账单报告" },
  { icon: "ri-coins-line", label: "理财", text: "我的理财持仓收益" },
  { icon: "ri-bank-card-line", label: "我的卡片", text: "我有哪些卡?" },
  { icon: "ri-alarm-warning-line", label: "挂失", text: "卡丢了先挂失" },
];
const QUICK_MORE = [
  { icon: "ri-line-chart-line", label: "额度管理", text: "信用卡额度太低能不能提额" },
  { icon: "ri-lock-unlock-line", label: "解除限制", text: "卡被限制了帮我解开" },
  { icon: "ri-add-circle-line", label: "办新卡", text: "想办一张新卡" },
  { icon: "ri-repeat-line", label: "订阅代扣", text: "订阅续费提醒" },
];
let quickMoreOpen = false;

/** 对话区的开场:一条问候,入口指向左上抽屉,不再堆一整屏宫格 */
function renderWelcome() {
  const name = profile?.displayName ?? "张先生";
  addMessage({
    role: "agent",
    text: `${name},您好!直接说即可。左上角是办事台:待确认、即将扣款和理财提醒都在那里,点开才会进对话,不会自动办理。`,
  });
}

function sectionTitle(text) {
  const t = document.createElement("div");
  t.className = "section-title";
  t.textContent = text;
  return t;
}

/** 抽屉头:姓名 + 总资产(概览数字放在最显眼的位置) */
function fillDrawerHead() {
  drawerName.textContent = profile?.displayName ?? "张先生";
  const accounts = profile?.accounts ?? [];
  const total = accounts.reduce((sum, a) => sum + (Number(a.balance) || 0), 0);
  drawerSub.textContent = `总资产 ¥${total.toLocaleString("zh-CN")}`;
}

/**
 * 常用流程的快捷入口。
 *
 * ★ 点一下**不是**直接执行,而是把模板实例化成一句话放进输入框:
 *   常用流程省的是打字,不是确认 —— 金额每次都可能不同,
 *   客户需要看到系统到底理解成了哪一句,才有机会改。
 *   (自动发送会让人担心"我点错了会不会直接转出去"。)
 */
function flowChip(f) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "flow-chip";

  const top = document.createElement("div");
  top.className = "flow-chip-name";
  const ico = document.createElement("i");
  ico.className = "ri-bookmark-3-line";
  ico.setAttribute("aria-hidden", "true");
  top.append(ico, document.createTextNode(f.name));

  const sub = document.createElement("div");
  sub.className = "flow-chip-say";
  sub.textContent = f.say ?? "";

  const meta = document.createElement("div");
  meta.className = "flow-chip-meta";
  meta.textContent = (f.useCount ?? 0) > 0 ? `用过 ${f.useCount} 次` : "还没用过";

  b.append(top, sub, meta);
  b.addEventListener("click", async () => {
    try {
      const r = await post("/api/flows/instantiate", {
        templateId: f.templateId,
        customerId: profile?.customerId,
      });
      inputEl.value = r.text;
      inputEl.focus();
      // 把光标放到句尾,客户直接改数字即可
      inputEl.setSelectionRange(r.text.length, r.text.length);
    } catch (err) {
      addMessage({ role: "agent", text: `这条常用流程取不出来了:${err.message}`, variant: "notice" });
    }
  });
  return b;
}

function uiRow(label, value) {
  const row = document.createElement("div");
  row.className = "ui-row";
  const l = document.createElement("div");
  l.className = "ui-row-label";
  l.textContent = label;
  const v = document.createElement("div");
  v.className = "ui-row-value";
  v.textContent = value;
  row.append(l, v);
  return row;
}

function quickButton(q) {
  const b = document.createElement("button");
  b.type = "button";
  const icon = document.createElement("i");
  icon.className = `qi ${q.icon}`;
  icon.setAttribute("aria-hidden", "true");
  const lab = document.createElement("span");
  lab.textContent = q.label;
  b.append(icon, lab);
  b.addEventListener("click", () => submit(q.text));
  return b;
}

function deskList(items) {
  const list = document.createElement("div");
  list.className = "desk-list";
  for (const item of items) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = `desk-item desk-${item.kind}`;
    const title = document.createElement("div");
    title.className = "desk-title";
    title.textContent = item.title;
    const detail = document.createElement("div");
    detail.className = "desk-detail";
    detail.textContent = item.detail;
    b.append(title, detail);
    b.addEventListener("click", () => {
      if (item.say) submit(item.say);
    });
    list.appendChild(b);
  }
  return list;
}

function updateDeskChrome() {
  const actions = profile?.personalization?.desk?.actions ?? [];
  const badge = $("menu-badge");
  if (badge) {
    badge.hidden = actions.length === 0;
    badge.textContent = actions.length > 9 ? "9+" : String(actions.length);
  }
  if (paneChat && !paneChat.hidden && paneAudit?.hidden && paneHistory?.hidden) {
    const thread = sessionTitle ? `本对话 · ${sessionTitle}` : "本对话连续办理";
    appbarSub.textContent = actions.length > 0 ? `${actions.length} 项待处理 · ${thread}` : thread;
  }
}

/** 办事台数据来自 /api/personalization,前端不自己拼到期日或待确认 */
async function refreshDesk() {
  try {
    const view = await get(`/api/personalization?sessionId=${encodeURIComponent(sessionId)}`);
    if (!profile) profile = {};
    profile.personalization = {
      flows: view.flows ?? [],
      suggestions: view.suggestions ?? [],
      history: view.history ?? profile.personalization?.history ?? [],
      desk: view.desk ?? { actions: [], notices: [] },
    };
    renderDrawer();
  } catch {
    updateDeskChrome();
  }
}

/** 抽屉:待您处理 / 为您留意 / 常用流程 / 常用服务 / 卡片 / 账户 */
function renderDrawer() {
  drawerBody.innerHTML = "";
  const hero = document.createElement("div");
  hero.className = "hero";

  const actions = profile?.personalization?.desk?.actions ?? [];
  const notices = profile?.personalization?.desk?.notices ?? [];
  if (actions.length > 0) {
    hero.appendChild(sectionTitle("待您处理"));
    hero.appendChild(deskList(actions));
  }
  if (notices.length > 0) {
    hero.appendChild(sectionTitle("为您留意"));
    hero.appendChild(deskList(notices));
  }

  /**
   * ★ 我的常用流程:最多两条,顺序跟服务端一致(最近保存或最近用过在前)。
   *
   *   不再固定只展示「useCount 最高的两条」—— 刚存的新流程 useCount 还是 0,
   *   若抽屉里永远占着演示阶段用过的旧条目,客户会以为没存上。
   *   `/api/personalization` 里的 flows 已按 lastUsedAt ?? createdAt 排好序。
   */
  const allFlows = profile?.personalization?.flows ?? [];
  const myFlows = allFlows.slice(0, 2);

  if (myFlows.length > 0) {
    hero.appendChild(sectionTitle("我的常用流程"));

    const strip = document.createElement("div");
    strip.className = "flows";
    for (const f of myFlows) {
      strip.appendChild(flowChip(f));
    }
    hero.appendChild(strip);
  }

  hero.appendChild(sectionTitle("常用服务"));
  const quick = document.createElement("div");
  quick.className = "quick";
  for (const q of QUICK) quick.appendChild(quickButton(q));
  if (quickMoreOpen) {
    for (const q of QUICK_MORE) quick.appendChild(quickButton(q));
  }
  const more = document.createElement("button");
  more.type = "button";
  more.dataset.keepOpen = "1";
  more.className = "quick-more";
  more.textContent = quickMoreOpen ? "收起" : "更多";
  more.addEventListener("click", () => {
    quickMoreOpen = !quickMoreOpen;
    renderDrawer();
  });
  quick.appendChild(more);
  hero.appendChild(quick);

  // 卡片概览
  const cards = profile?.cards ?? [];
  if (cards.length > 0) {
    hero.appendChild(sectionTitle(`我的卡片(${cards.length} 张)`));

    const strip = document.createElement("div");
    strip.className = "mini-cards";
    for (const c of cards) {
      strip.appendChild(miniCard(c));
    }
    hero.appendChild(strip);
  }

  // 账户概览
  hero.appendChild(sectionTitle("账户概览"));
  const note = document.createElement("div");
  note.className = "ui-card";
  const nb = document.createElement("div");
  nb.className = "ui-card-body";

  // 总资产突出为大数字,各账户以小字逐行列出,避免一行挤多个账户
  const accounts = profile?.accounts ?? [];
  const total = accounts.reduce((sum, a) => sum + (Number(a.balance) || 0), 0);

  const totalRow = uiRow("总资产", `¥${total.toLocaleString("zh-CN")}`);
  totalRow.classList.add("total");
  nb.appendChild(totalRow);
  for (const a of accounts) {
    const r = uiRow(`尾号 ${a.maskedNo.slice(-4)}`, `¥${Number(a.balance).toLocaleString("zh-CN")}`);
    r.classList.add("acct");
    nb.appendChild(r);
  }
  nb.appendChild(uiRow("风险等级", profile?.wealth?.assessed ? `${profile.wealth.level}(${profile.wealth.levelLabel})` : "未测评"));

  note.appendChild(nb);
  hero.appendChild(note);

  drawerBody.appendChild(hero);
  updateDeskChrome();
}

function miniCard(c) {
  const el = document.createElement("div");
  el.className = "mini-card";

  // 状态 → 标签。卡片本体一律白底,异常状态用标签颜色表达,不再整张变色
  const status = document.createElement("span");
  status.className = "mc-status";
  status.textContent = c.restrictionCauseLabel ? `${c.statusLabel} · ${c.restrictionCauseLabel}` : c.statusLabel;
  if (c.status === "lost" || c.status === "frozen" || c.restrictionCause) status.classList.add("bad");
  else if (c.status === "pending_activation" || c.status === "replacement_in_transit") status.classList.add("warn");
  else status.classList.add("ok");

  const top = document.createElement("div");
  top.className = "mc-top";
  const name = document.createElement("div");
  name.className = "mc-name";
  name.textContent = c.productName;
  top.append(name, status);

  const no = document.createElement("div");
  no.className = "mc-no";
  no.textContent = `**** ${c.last4}`;

  const foot = document.createElement("div");
  foot.className = "mc-foot";
  const left = document.createElement("span");
  left.textContent = c.kindLabel;
  const right = document.createElement("span");
  right.className = "mc-limit";
  right.textContent = c.creditLimit != null ? `额度 ¥${Number(c.creditLimit).toLocaleString("zh-CN")}` : "借记卡";
  foot.append(left, right);

  el.append(top, no, foot);

  el.addEventListener("click", () => submit(`尾号${c.last4}那张额度多少`));
  return el;
}

// ============================================================================
// 历史记录(只读)
//
// ★ 三条边界,缺一不可:
//   ① 只读:详情里**不渲染任何**确认/取消/再确认按钮 —— 服务端也不返回 pendingId。
//      客户想再办一次,只能走「再办一次」→ 新会话 → 重新确认与验证。
//   ② 状态与色调全部用服务端给的 statusLabel / tone,前端只负责上色(红线 #8)。
//   ③ 「再办一次」= 换一个新 sessionId + 预填上一轮用户原话,
//      绝不是"复用上一笔的待办"—— 旧会话的待办不受影响。
// ============================================================================

const REPLAY_PREFILL_KEY = "bank-agent-replay-prefill";

/**
 * ★ 列表与详情共用这一句,所以它必须覆盖两种粒度:
 *   列表的一行 = **一笔业务**(台账粒度);详情 = 这笔业务 + 它所属对话的回放。
 *   两种视图都**不能办事** —— 这句话是界面上的第一层,后端"不返回 pendingId"
 *   与跨会话确认拒绝(G2/G3)是第二、第三层。
 */
/** 历史列表当前筛的业务标签。空字符串 = 全部。标签来自服务端的 family,前端不自己归类。 */
let historyFamilyFilter = "";

const HISTORY_BANNER =
  "历史记录仅供查看,不能在这里确认或撤销任何操作。要再办一次,在详情里点『再办一次』—— 会重新走确认与验证。";

function fmtHistoryTime(ts) {
  const d = new Date(ts);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

async function openHistory() {
  if (!paneAudit.hidden) closeAudit();
  paneChat.hidden = true;
  paneHistory.hidden = false;
  composer.hidden = true;
  btnBack.hidden = false;
  appbarSub.textContent = "历史记录 · 只读";
  await refreshHistory();
}

function closeHistory() {
  paneHistory.hidden = true;
  paneChat.hidden = false;
  composer.hidden = false;
  btnBack.hidden = true;
  updateDeskChrome();
  scrollToEnd();
}

/**
 * 列表:一行**一笔业务**(台账粒度),按时间倒序。
 *
 * ★ 为什么不是一行一个会话(这一版改掉的东西):
 *   前端一个标签页自始至终只有一个 sessionId,所以"一天办了好几件事"全都落在
 *   同一个会话里。按会话出行的话,第 2 笔起就看不见了 —— 标题只认第一笔,
 *   状态是全会话的聚合(一笔「已提交待审核」会盖住另一笔「已转账成功」)。
 *   客户在历史里找的是**那一笔**,行的身份就必须是那一笔(opId)。
 *
 *   会话依旧是可回放的容器:每行带 sessionId,点进去看那次对话的原话与卡片。
 */
async function refreshHistory() {
  historyBody.innerHTML = "";
  let data;
  try {
    const q = new URLSearchParams({
      current: sessionId,
      customerId: profile?.customerId ?? "",
      limit: "50",
    });
    data = await get(`/api/ledger/recent?${q.toString()}`);
  } catch (err) {
    historyBody.appendChild(historyNotice(`读取历史失败:${err.message}`));
    return;
  }

  const operations = data.operations ?? [];
  if (operations.length === 0) {
    historyBody.appendChild(historyNotice("还没有历史记录。办完第一件事之后,这里会有可回看的办理记录。"));
    return;
  }

  historyBody.appendChild(historyBanner());
  const filters = historyFilters(operations);
  if (filters) historyBody.appendChild(filters);

  const shown = historyFamilyFilter ? operations.filter((op) => op.family === historyFamilyFilter) : operations;
  if (shown.length === 0) {
    historyBody.appendChild(historyNotice("这一类业务在记录里还没有。"));
    return;
  }

  const list = document.createElement("div");
  list.className = "hr-list";
  for (const op of shown) list.appendChild(historyItem(op));
  historyBody.appendChild(list);
}

function historyFilters(operations) {
  const families = [];
  for (const op of operations) {
    if (op.family && !families.includes(op.family)) families.push(op.family);
  }
  if (families.length < 2) return null;
  if (historyFamilyFilter && !families.includes(historyFamilyFilter)) historyFamilyFilter = "";

  const bar = document.createElement("div");
  bar.className = "hr-filters";
  const add = (label, value) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = historyFamilyFilter === value ? "hr-filter on" : "hr-filter";
    button.textContent = label;
    button.addEventListener("click", () => {
      historyFamilyFilter = value;
      void refreshHistory();
    });
    bar.appendChild(button);
  };
  add("全部", "");
  for (const family of families) add(family, family);
  return bar;
}

function historyBanner() {
  const banner = document.createElement("div");
  banner.className = "hr-banner";
  banner.textContent = HISTORY_BANNER;
  return banner;
}

function historyBackButton() {
  const back = document.createElement("button");
  back.type = "button";
  back.className = "hr-back";
  back.textContent = "返回列表";
  back.addEventListener("click", () => {
    void refreshHistory();
  });
  return back;
}

function historyNotice(text) {
  const d = document.createElement("div");
  d.className = "hr-empty";
  d.textContent = text;
  return d;
}

/**
 * 一行 = 一笔业务。
 *
 * ★ 这一行只讲**这一笔**的状态:标题用它自己的 family/subject,徽标用它自己的
 *   statusLabel —— 不替同会话的其它业务发言,也不被它们盖住。
 */
function historyItem(op) {
  const item = document.createElement("button");
  item.type = "button";
  item.className = op.isCurrent ? "hr-item active" : "hr-item";

  const time = document.createElement("span");
  time.className = "hr-time";
  time.textContent = fmtHistoryTime(op.createdAt);

  const title = document.createElement("span");
  title.className = "hr-title";
  title.textContent = operationTitle(op);

  const status = document.createElement("span");
  status.className = `hr-status ${op.tone}`;
  status.textContent = op.statusLabel;

  const sub = document.createElement("span");
  sub.className = "hr-sub";
  sub.textContent = [
    fmtHistoryAmount(op.amount),
    op.reference ? `流水号 …${String(op.reference).slice(-4)}` : "",
    op.isCurrent ? "本次对话办的" : "",
  ]
    .filter(Boolean)
    .join(" · ");

  item.append(time, title, status, sub);
  item.addEventListener("click", () => {
    void openOperation(op);
  });
  return item;
}

/** 「转账汇款 · 王秀兰」:两个字段都是服务端给的,前端只做拼接(红线 #8) */
function operationTitle(op) {
  return [op.family, op.subject].filter(Boolean).join(" · ") || op.capability || "业务记录";
}

/** 金额:只格式化服务端给的真实数字,不做任何业务判断 */
function fmtHistoryAmount(amount) {
  if (typeof amount !== "number") return "";
  return `¥${amount.toLocaleString("zh-CN", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

/** 点一行:看这一笔的详情 + 它所属那次对话的回放 */
async function openOperation(op) {
  /**
   * ★ 能不能回放由服务端说了算(hasSession = 那次对话还在保留期内)。
   *   不能回放时也不给客户一个点不动的行 —— 退回"只有这一笔"的详情。
   */
  const replayable = op.hasSession ?? Boolean(op.sessionId);
  if (!replayable) {
    await openLedgerEntry(op);
    return;
  }
  await openSession(op.sessionId, op.opId);
}

/** 早于会话记录功能的台账条目:没有可回放的对话,只能看这一笔本身 */
async function openLedgerEntry(op) {
  historyBody.innerHTML = "";
  if (!op.opId) {
    historyBody.appendChild(historyNotice("这条记录没有可查看的详情。"));
    historyBody.appendChild(historyBackButton());
    return;
  }
  try {
    const q = new URLSearchParams({ customerId: profile?.customerId ?? "" });
    const data = await get(`/api/ledger/${encodeURIComponent(op.opId)}?${q.toString()}`);
    renderLedgerEntry(data.operation);
  } catch (err) {
    historyBody.appendChild(historyNotice(`读取这条记录失败:${err.message}`));
    historyBody.appendChild(historyBackButton());
  }
}

/** 详情:只读回放(复用现有 renderText,不渲染任何操作按钮) */
async function openSession(id, focusOpId) {
  historyBody.innerHTML = "";
  try {
    const q = new URLSearchParams({ customerId: profile?.customerId ?? "" });
    const data = await get(`/api/sessions/${encodeURIComponent(id)}?${q.toString()}`);
    renderSession(data.session, focusOpId);
  } catch (err) {
    historyBody.appendChild(historyNotice(`读取这次对话失败:${err.message}`));
    historyBody.appendChild(historyBackButton());
  }
}

function renderSession(s, focusOpId) {
  const wrap = document.createElement("div");
  wrap.className = "hr-detail";

  wrap.appendChild(historyBanner());

  const head = document.createElement("div");
  head.className = "hr-detail-head";
  const title = document.createElement("div");
  title.className = "hr-detail-title";
  title.textContent = s.title;
  const meta = document.createElement("div");
  meta.className = "hr-detail-meta";
  meta.textContent = `${fmtHistoryTime(s.startedAt)} · ${s.statusLabel}`;
  head.append(title, meta);
  wrap.appendChild(head);

  /**
   * ★ 会话里的每一笔业务都列出来。
   *
   *   会话头的 statusLabel 是"本次对话最需要关注的一个",它是会话级口径;
   *   而客户常常是**从某一笔点进来**的 —— 所以这里必须把同会话的其它几笔
   *   一并摆出来,并把点进来的那一笔高亮,让他看清"这次一共办了几件、
   *   哪一件是我刚点的、其余各自是什么状态"。
   */
  /**
   * ★ 用 businesses(一笔业务一行),不用 operations(事件流水)。
   *   事件流水里一笔转账是「待你确认」+「已转账成功」两行 ——
   *   拿它数笔数会把一件事数成两件。两者都由服务端给,前端只挑该显示的那份。
   */
  const ops = s.businesses ?? s.operations ?? [];
  if (ops.length > 0) {
    const label = document.createElement("div");
    label.className = "hr-ops-label";
    label.textContent = `这次对话办了 ${ops.length} 笔业务`;
    wrap.appendChild(label);
    wrap.appendChild(renderOperations(ops, focusOpId));
  }

  const turns = document.createElement("div");
  turns.className = "hr-turns";
  for (const t of s.turns ?? []) {
    const row = document.createElement("div");
    row.className = `hr-turn ${t.role}`;

    const role = document.createElement("div");
    role.className = "hr-role";
    role.textContent = t.role === "user" ? "您" : "助手";

    const text = document.createElement("div");
    text.className = "hr-turn-text";
    text.appendChild(renderText(t.text));

    row.append(role, text);

    if (t.cardTitle) {
      const card = document.createElement("div");
      card.className = "hr-turn-card";
      card.textContent = `卡片:${t.cardTitle}`;
      row.appendChild(card);
    }
    turns.appendChild(row);
  }
  wrap.appendChild(turns);

  /**
   * ★ 这里只有两个按钮:"再办一次"与"返回列表"。
   *   没有确认、没有取消、没有"继续办理" —— 历史不能办任何事。
   */
  const replay = document.createElement("button");
  replay.type = "button";
  replay.className = "hr-replay";
  replay.textContent = "再办一次";
  replay.addEventListener("click", () => replaySession(s));
  wrap.appendChild(replay);

  wrap.appendChild(historyBackButton());

  historyBody.appendChild(wrap);
}

/**
 * 台账条目的清单(会话详情里用,也用于没有会话可回放的老条目)。
 * focusOpId 是客户点进来的那一笔 —— 只做视觉高亮,不改任何数据。
 */
function renderOperations(ops, focusOpId) {
  const list = document.createElement("div");
  list.className = "hr-ops";
  for (const op of ops) {
    const row = document.createElement("div");
    row.className = op.opId && op.opId === focusOpId ? "hr-op active" : "hr-op";

    const title = document.createElement("div");
    title.className = "hr-op-title";
    title.textContent = operationTitle(op);

    const status = document.createElement("span");
    status.className = `hr-status ${op.tone}`;
    status.textContent = op.statusLabel;

    const meta = document.createElement("div");
    meta.className = "hr-op-meta";
    meta.textContent = [
      fmtHistoryTime(op.createdAt),
      fmtHistoryAmount(op.amount),
      op.reference ? `流水号 ${op.reference}` : "",
      op.detail ?? "",
    ]
      .filter(Boolean)
      .join(" · ");

    row.append(title, status, meta);
    list.appendChild(row);
  }
  return list;
}

/** 没有关联会话的老台账条目:只呈现这一笔本身(口径与详情页一致) */
function renderLedgerEntry(op) {
  const wrap = document.createElement("div");
  wrap.className = "hr-detail";

  wrap.appendChild(historyBanner());

  const head = document.createElement("div");
  head.className = "hr-detail-head";
  const title = document.createElement("div");
  title.className = "hr-detail-title";
  title.textContent = operationTitle(op);
  const meta = document.createElement("div");
  meta.className = "hr-detail-meta";
  meta.textContent = `${fmtHistoryTime(op.createdAt)} · ${op.statusLabel}`;
  head.append(title, meta);
  wrap.appendChild(head);

  wrap.appendChild(renderOperations([op], op.opId));

  const note = document.createElement("div");
  note.className = "hr-empty";
  note.textContent = "这条记录没有可回看的对话(早于会话回放功能,或那次对话已超过保留期)。下面是它自己的业务状态。";
  wrap.appendChild(note);

  wrap.appendChild(historyBackButton());

  historyBody.appendChild(wrap);
}

/**
 * 「再办一次」:换新会话 + 预填上一轮用户原话。
 *
 * ★ 为什么必须换 sessionId:旧会话里可能还挂着一笔待确认动作。
 *   复用旧会话 = 把客户带回那个"还有一笔没处理"的状态,甚至让他以为
 *   这次点的是新业务、实际确认的是旧待办。换一个新会话,旧待办原封不动。
 *
 * ★ 为什么用刷新页面而不是就地清空:sessionId 是页面加载时确定的常量,
 *   就地改它会让"当前页面的对话"与"服务端认为的会话"错位。
 *   刷新是最不容易出错的实现 —— 并且它天然把聊天区清成"新会话"。
 */
function replaySession(s) {
  const lastUser = [...(s.turns ?? [])].reverse().find((t) => t.role === "user");
  const fresh = `web_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 8)}`;
  sessionStorage.setItem(SESSION_KEY, fresh);
  if (lastUser?.text) sessionStorage.setItem(REPLAY_PREFILL_KEY, lastUser.text);
  location.reload();
}

// ============================================================================
// 审计面板
// ============================================================================

let auditTimer = null;

async function openAudit() {
  if (!paneHistory.hidden) closeHistory();
  paneChat.hidden = true;
  paneAudit.hidden = false;
  composer.hidden = true;
  btnBack.hidden = false;
  appbarSub.textContent = "审计与安全";
  await refreshAudit();
  auditTimer = setInterval(refreshAudit, 4000);
}

function closeAudit() {
  if (auditTimer) clearInterval(auditTimer);
  auditTimer = null;
  // 下次进来永远从哈希链开始,并恢复轮询 —— 不要停在上一回看的某条 trace 上
  auditMode = "chain";
  auditTraceId = null;
  paneAudit.hidden = true;
  paneChat.hidden = false;
  composer.hidden = false;
  btnBack.hidden = true;
  updateDeskChrome();
  scrollToEnd();
}

/**
 * 审计面板的两种看法:
 *   chain —— 区块浏览器:每条事件是一块,能展开看哈希与载荷,能顺着 prevHash 核对;
 *   trace —— 全链路胶片:同一 traceId 的事件按发生顺序排成瀑布,看一次业务走了哪些环节。
 * trace 是历史定格,不轮询;chain 保持 4 秒轮询(演示时能看到新块长出来)。
 */
let auditMode = "chain";
let auditTraceId = null;
/** 已展开的区块(seq)。轮询重绘后仍保持展开,不把用户正在看的那块合起来 */
const openBlocks = new Set();

/** 事件类型 → 人话。与 LANE_TEXT 同级:翻译枚举,不含任何业务判断。 */
const AUDIT_EVENT_TEXT = {
  envelope_received: "收到请求",
  intent_parsed: "意图解析",
  plan_created: "生成执行计划",
  policy_evaluated: "策略裁决",
  confirm_presented: "展示确认卡",
  strong_auth_requested: "要求本人验证",
  strong_auth_completed: "本人验证通过",
  execution_started: "开始执行",
  execution_completed: "执行完成",
  handoff_to_human: "转人工审批",
  compensation_started: "开始补偿",
  compensation_completed: "补偿完成",
};

function auditEventLabel(type) {
  return AUDIT_EVENT_TEXT[type] ?? type;
}

async function copyHash(text, btn) {
  try {
    await navigator.clipboard.writeText(text);
    const old = btn.textContent;
    btn.textContent = "已复制";
    setTimeout(() => {
      btn.textContent = old;
    }, 1200);
  } catch {
    btn.textContent = "复制失败";
  }
}

/** 一条哈希:等宽缩略 + 点击复制完整值(取证时要的是完整的 64 位) */
function hashLine(label, full, short) {
  const row = document.createElement("div");
  row.className = "blk-hash-row";
  const l = document.createElement("span");
  l.className = "blk-hash-label";
  l.textContent = label;
  const v = document.createElement("code");
  v.className = "blk-hash-val";
  v.textContent = full || short || "—";
  row.append(l, v);
  if (full) {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "blk-copy";
    b.textContent = "复制";
    b.addEventListener("click", (ev) => {
      ev.stopPropagation();
      void copyHash(full, b);
    });
    row.appendChild(b);
  }
  return row;
}

/** 单个区块:头部永远可见,哈希与载荷点开了才看 */
function auditBlockEl(e) {
  const det = document.createElement("details");
  det.className = "blk";
  if (e.sessionId === sessionId) det.classList.add("hl");
  det.open = openBlocks.has(e.seq);
  det.addEventListener("toggle", () => {
    if (det.open) openBlocks.add(e.seq);
    else openBlocks.delete(e.seq);
  });

  const sum = document.createElement("summary");
  sum.className = "blk-head";
  const seq = document.createElement("span");
  seq.className = "blk-seq";
  seq.textContent = `#${e.seq}`;
  const type = document.createElement("span");
  type.className = "blk-type";
  type.textContent = auditEventLabel(e.type);
  const time = document.createElement("span");
  time.className = "blk-time";
  time.textContent = new Date(e.ts).toLocaleTimeString("zh-CN");
  sum.append(seq, type, time);
  det.appendChild(sum);

  const body = document.createElement("div");
  body.className = "blk-body";
  body.appendChild(hashLine("本块哈希", e.hash, e.hashShort));
  body.appendChild(hashLine("前块哈希", e.prevHash, e.prevHashShort));

  const meta = document.createElement("div");
  meta.className = "blk-meta";
  meta.textContent = `${e.type} · ${e.channel ?? "-"} · ${new Date(e.ts).toLocaleString("zh-CN")}`;
  body.appendChild(meta);

  const openTraceBtn = document.createElement("button");
  openTraceBtn.type = "button";
  openTraceBtn.className = "blk-trace-btn";
  openTraceBtn.innerHTML = '<i class="ri-node-tree" aria-hidden="true"></i>看这次业务的全链路';
  openTraceBtn.addEventListener("click", () => void openTrace(e.traceId));
  body.appendChild(openTraceBtn);

  const pre = document.createElement("pre");
  pre.className = "blk-payload";
  pre.textContent = JSON.stringify(e.payload ?? {}, null, 2);
  body.appendChild(pre);

  det.appendChild(body);
  return det;
}

/**
 * 全链路瀑布:同一 traceId 下真实发生过的事件,按时间顺序排开。
 *
 * ★ 与流程卡的关系:流程卡是「给客户看的人话」,这里是「给评委/审计看的原始证据」。
 *   两者读的是同一条链,所以不存在界面一套、审计一套的问题。
 */
function traceWaterfall(events) {
  const wrap = document.createElement("div");
  wrap.className = "wf";
  const rows = [...events].sort((a, b) => a.ts - b.ts || a.seq - b.seq);
  const t0 = rows[0]?.ts ?? 0;
  const tEnd = rows[rows.length - 1]?.ts ?? t0;
  const span = Math.max(1, tEnd - t0);

  for (const e of rows) {
    const row = document.createElement("details");
    row.className = "wf-row";

    const sum = document.createElement("summary");
    sum.className = "wf-head";

    const offset = document.createElement("span");
    offset.className = "wf-offset";
    offset.textContent = `+${e.ts - t0}ms`;

    const rail = document.createElement("span");
    rail.className = "wf-rail";
    const dot = document.createElement("span");
    dot.className = "wf-dot";
    rail.appendChild(dot);

    const label = document.createElement("span");
    label.className = "wf-label";
    label.textContent = auditEventLabel(e.type);

    // 位置条:这个事件在本次业务的时间轴上发生在哪 —— 一眼看出哪一段最耗时
    const bar = document.createElement("span");
    bar.className = "wf-bar";
    const fill = document.createElement("span");
    fill.style.left = `${((e.ts - t0) / span) * 100}%`;
    bar.appendChild(fill);

    sum.append(offset, rail, label, bar);
    row.appendChild(sum);

    const body = document.createElement("div");
    body.className = "wf-body";
    const seq = document.createElement("div");
    seq.className = "blk-meta";
    seq.textContent = `#${e.seq} · ${e.type} · ${new Date(e.ts).toLocaleTimeString("zh-CN")}`;
    body.appendChild(seq);
    const pre = document.createElement("pre");
    pre.className = "blk-payload";
    pre.textContent = JSON.stringify(e.payload ?? {}, null, 2);
    body.appendChild(pre);
    row.appendChild(body);

    wrap.appendChild(row);
  }
  return wrap;
}

async function openTrace(traceId) {
  if (!traceId) return;
  auditMode = "trace";
  auditTraceId = traceId;
  // 历史定格,不轮询 —— 否则每 4 秒重绘会把用户展开的 payload 合起来
  if (auditTimer) clearInterval(auditTimer);
  auditTimer = null;
  appbarSub.textContent = "全链路证据";
  await refreshAudit();
}

function backToChain() {
  auditMode = "chain";
  auditTraceId = null;
  appbarSub.textContent = "审计与安全";
  void refreshAudit();
  if (!auditTimer) auditTimer = setInterval(refreshAudit, 4000);
}

async function refreshAudit() {
  try {
    if (auditMode === "trace" && auditTraceId) {
      const data = await get(`/api/audit/recent?traceId=${encodeURIComponent(auditTraceId)}&limit=200`);
      const events = data.events ?? [];
      auditBody.innerHTML = "";

      const back = document.createElement("button");
      back.type = "button";
      back.className = "wf-back";
      back.innerHTML = '<i class="ri-arrow-left-s-line" aria-hidden="true"></i>返回哈希链';
      back.addEventListener("click", backToChain);
      auditBody.appendChild(back);

      const hero = document.createElement("div");
      hero.className = "audit-hero";
      const title = document.createElement("div");
      title.textContent = "一次业务的全过程";
      const meta = document.createElement("div");
      meta.className = "audit-meta";
      const ts = events.map((e) => e.ts);
      const span = ts.length > 1 ? Math.max(...ts) - Math.min(...ts) : 0;
      meta.textContent = `${events.length} 个事件 · 跨度 ${span}ms · ${auditTraceId}`;
      hero.append(title, meta);
      auditBody.appendChild(hero);

      auditBody.appendChild(traceWaterfall(events));
      return;
    }

    const [verify, recent] = await Promise.all([
      get("/api/audit/verify"),
      get("/api/audit/recent?limit=40"),
    ]);
    auditBody.innerHTML = "";

    const hero = document.createElement("div");
    hero.className = "audit-hero";
    const title = document.createElement("div");
    title.innerHTML = verify.intact
      ? '哈希链校验:<span class="ok"><i class="ri-checkbox-circle-line" aria-hidden="true"></i>完整,未被篡改</span>'
      : `哈希链校验:<span class="bad"><i class="ri-close-circle-line" aria-hidden="true"></i>断点位于 seq=${verify.brokenAtSeq}</span>`;
    const meta = document.createElement("div");
    meta.className = "audit-meta";
    meta.textContent =
      `事件总数 ${verify.total} · 每条哈希 = SHA256(seq|ts|type|payload|prevHash)。` +
      "点开任意一块可复制完整哈希、核对前块链接,或看这次业务的全链路。";
    hero.append(title, meta);
    auditBody.appendChild(hero);

    const list = document.createElement("div");
    list.className = "audit-list";
    const events = [...(recent.events ?? [])].reverse();
    for (const e of events) {
      const blk = auditBlockEl(e);
      // 校验已定位到断点:把那块标出来,而不是只在一行文字里报个序号
      if (!verify.intact && e.seq === verify.brokenAtSeq) blk.classList.add("broken");
      list.appendChild(blk);
    }
    auditBody.appendChild(list);
  } catch (err) {
    auditBody.innerHTML = "";
    const d = document.createElement("div");
    d.className = "audit-hero";
    d.textContent = `读取审计失败:${err.message}`;
    auditBody.appendChild(d);
  }
}

btnAudit.addEventListener("click", () => {
  if (paneAudit.hidden) openAudit();
  else closeAudit();
});
btnHistory.addEventListener("click", () => {
  if (paneHistory.hidden) openHistory();
  else closeHistory();
});
// 返回按钮按"当前在哪个面板"决定退到哪 —— 历史与审计共用同一个返回位
btnBack.addEventListener("click", () => {
  if (!paneHistory.hidden) closeHistory();
  else closeAudit();
});

// ============================================================================
// 启动
// ============================================================================

/**
 * 把当前 sessionId 上已经落盘的原话画回对话区。
 *
 * 刷新、重开页面都还是这一段,不能画成空白新对话 ——
 * 服务端的待确认还挂在这段上,空白界面会让人不知道「确认」确认的是哪一笔。
 * 这里只回放文本。确认按钮只在这笔待办仍属于本会话时补上。
 */
async function restoreCurrentSession() {
  let session = null;
  try {
    session = (await get(`/api/sessions/${encodeURIComponent(sessionId)}`)).session;
  } catch {
    session = null;
  }
  const turns = session?.turns ?? [];
  if (turns.length === 0) {
    renderThreadTags([]);
    renderWelcome();
    return;
  }
  sessionTitle = session.title && session.title !== "新会话" ? session.title : "";
  renderThreadTags(session.tags ?? []);
  for (const turn of turns) {
    addMessage({ role: turn.role === "user" ? "user" : "agent", text: turn.text });
  }
  updateDeskChrome();
  await appendPendingCard();
}

/** 本段对话的业务标签。同一段可以有多笔,标签只标明办过什么,不新开会话。 */
function renderThreadTags(tags) {
  const bar = $("thread-tags");
  if (!bar) return;
  bar.replaceChildren();
  if (!tags || tags.length === 0) {
    bar.hidden = true;
    return;
  }
  bar.hidden = false;
  const label = document.createElement("span");
  label.className = "thread-tags-label";
  label.textContent = "本段";
  bar.appendChild(label);
  for (const tag of tags) {
    const chip = document.createElement("span");
    chip.className = "thread-tag";
    chip.textContent = tag;
    bar.appendChild(chip);
  }
}

async function refreshThreadTags() {
  try {
    const session = (await get(`/api/sessions/${encodeURIComponent(sessionId)}`)).session;
    if (session?.title && session.title !== "新会话") sessionTitle = session.title;
    renderThreadTags(session?.tags ?? []);
    updateDeskChrome();
  } catch {
    // 标签是辨认用的,取不到不影响继续办
  }
}

async function boot() {
  try {
    profile = await get(`/api/demo/profile?sessionId=${encodeURIComponent(sessionId)}`);
  } catch {
    profile = null;
  }

  renderDrawer();
  fillDrawerHead();
  await restoreCurrentSession();
  inputEl.focus();

  // 「再办一次」后的预填:上一轮用户原话(读完即删,避免下次刷新又冒出来)
  const prefill = sessionStorage.getItem(REPLAY_PREFILL_KEY);
  if (prefill) {
    sessionStorage.removeItem(REPLAY_PREFILL_KEY);
    inputEl.value = prefill;
    inputEl.focus();
  }
}

boot();
