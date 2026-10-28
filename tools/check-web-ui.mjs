/**
 * 移动端 App 页面的静态交叉校验。
 *
 * 为什么需要它:这个页面没法在 CI 里跑浏览器(沙箱会挡住 Chrome 的命名管道),
 * 而"JS 里引用了不存在的 DOM id""用了 CSS 里没定义的 class"
 * 正是这类页面最常见的低级故障 —— 页面能打开,但某些功能静默失效。
 * 这个脚本把这两类问题变成可自动发现的。
 *
 * 用法:node tools/check-web-ui.mjs        (在 bank-agent 目录下运行)
 */
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const require = createRequire(import.meta.url);
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const pub = join(root, "packages/server/public");

const html = readFileSync(join(pub, "index.html"), "utf8");
const js = readFileSync(join(pub, "app.js"), "utf8");
const css = readFileSync(join(pub, "app.css"), "utf8");

let failed = 0;
const fail = (msg) => {
  console.log("  ✗ " + msg);
  failed++;
};
const pass = (msg) => console.log("  ✓ " + msg);

// ---- 1. 语法(app.js 必须能被解析) ----
console.log("1. app.js 语法");
try {
  // typescript 装在 bank-agent 里,所以要按那个目录去解析
  const requireFromApp = createRequire(join(root, "package.json"));
  const ts = requireFromApp("typescript");
  const sf = ts.createSourceFile("app.js", js, ts.ScriptTarget.ESNext, true, ts.ScriptKind.JS);
  const diags = sf.parseDiagnostics ?? [];
  if (diags.length === 0) pass("解析零错误");
  else {
    for (const d of diags.slice(0, 5)) {
      const p = sf.getLineAndCharacterOfPosition(d.start);
      fail(`L${p.line + 1}:${p.character + 1} ${ts.flattenDiagnosticMessageText(d.messageText, " ")}`);
    }
  }
} catch (e) {
  fail("无法加载 typescript:" + e.message);
}

// ---- 2. 引用的 DOM id 必须存在 ----
console.log("2. DOM id 引用");
const htmlIds = new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
const jsIds = new Set([...js.matchAll(/\$\("([^"]+)"\)/g)].map((m) => m[1]));
const missingIds = [...jsIds].filter((id) => !htmlIds.has(id));
if (missingIds.length === 0) pass(`${jsIds.size} 个 id 全部存在`);
else fail("缺失的 id: " + missingIds.join(", "));

// ---- 3. 用到的 class 必须有样式定义 ----
console.log("3. class 与样式");
/** 只接受合法的 class 名;模板字面量与三元表达式里的碎片会被这里过滤掉 */
const CLASS_RE = /^[a-z][a-z0-9-]*$/;
const jsClasses = new Set();
for (const m of js.matchAll(/className\s*=\s*"([^"]*)"/g)) {
  for (const c of m[1].split(/\s+/)) if (c) jsClasses.add(c);
}
for (const m of js.matchAll(/classList\.add\((?:"|')([^"']+)(?:"|')\)/g)) jsClasses.add(m[1]);
for (const m of js.matchAll(/`([a-z][a-z0-9-]*)(\s+\$\{[^}]*\})?`/g)) {
  if (CLASS_RE.test(m[1])) jsClasses.add(m[1]);
}
const cssClasses = new Set([...css.matchAll(/\.([a-zA-Z][\w-]*)/g)].map((m) => m[1]));
// 纯语义状态类允许没有样式
const allowed = new Set(["agent", "md-strong", "md-star"]);
/**
 * Remix Icon 的类名由 CDN 字体样式表提供(index.html 里的 remixicon.css),
 * 本地 app.css 里当然找不到 —— 它们不是"漏定义的样式",而是图标字体。
 * 这里显式放行 `ri-` 前缀,同时**保留**其它缺失 class 的检查 ——
 * 把整条检查关掉就等于放走了真正的问题(写了 class 却没有样式 = 静默失效)。
 */
const realMissing = [...jsClasses].filter(
  (c) => CLASS_RE.test(c) && !cssClasses.has(c) && !allowed.has(c) && !c.startsWith("ri-"),
);
if (realMissing.length === 0) pass(`${[...jsClasses].filter((c) => CLASS_RE.test(c)).length} 个 class 全部有样式(或属允许的状态类)`);
else fail("未定义样式的 class: " + realMissing.join(", "));

// ---- 4. 前端不得包含业务判断(架构约束) ----
console.log("4. 前端零业务判断(架构约束)");
const forbidden = [
  [/includes\(\s*["'`](卡|挂失|补卡|额度|转账|赎回)/, "出现了按业务关键词的分支判断"],
  [/=== ?["'`](card|transfer|wealth)\./, "出现了按能力名分派"],
  [/sessionStorage\.setItem\([^)]*(status|card|limit)/, "把业务状态缓存在前端"],
];
let hit = 0;
for (const [re, why] of forbidden) {
  if (re.test(js)) {
    fail(why + " —— " + re);
    hit++;
  }
}
if (hit === 0) pass("未发现前端业务判断:状态与裁决全部来自服务端");

// ---- 5. 移动端适配的硬要求 ----
console.log("5. 移动端适配");
const checks = [
  [/viewport-fit=cover/, "index.html 缺少 viewport-fit=cover(刘海/手势条区域无法延伸)"],
  [/100dvh/, "CSS 未使用 dvh —— 移动端地址栏收放会把输入框顶出屏幕"],
  [/env\(safe-area-inset-bottom/, "CSS 未处理 safe-area-inset-bottom(home 指示条会压住输入框)"],
  [/font-size:\s*16px/, "输入框字号未设为 16px —— iOS 聚焦时会自动放大整页"],
];
let miss = 0;
for (const [re, why] of checks) {
  const hay = re.source.includes("safe-area") || re.source.includes("dvh") || re.source.includes("viewport") ? html + css : css;
  if (!re.test(hay)) {
    fail(why);
    miss++;
  }
}
if (miss === 0) pass("viewport / dvh / safe-area / 输入框字号 四项齐全");

console.log("");
if (failed === 0) {
  console.log("全部通过 ✓");
  process.exit(0);
}
console.log(`${failed} 项未通过 ✗`);
process.exit(1);
