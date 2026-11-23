"use strict";

const find = selector => document.querySelector(selector);
const mode = find('[name="mode"]');
if (mode) {
  const base = find('[name="base"]');
  const upgrade = find('[name="upgrade"]');
  function showScope() {
    const live = mode.value === "live";
    find("#live-fields").hidden = !live;
    base.required = live;
    base.disabled = !live;
    let eligible = false;
    try {
      const url = new URL(base.value);
      eligible = live && url.protocol === "http:" && !url.port && !url.search && !url.hash && !url.username && !url.password
        && !/[%\\@?#\s]/.test(base.value) && !base.value.split("/").some(part => part === "." || part === "..")
        && /^\/(?:[A-Za-z0-9_~./-]*)$/.test(url.pathname) && !url.pathname.includes("//");
    } catch {}
    upgrade.closest("label").hidden = !eligible;
    upgrade.disabled = !eligible;
    if (!eligible) upgrade.checked = false;
  }
  mode.addEventListener("change", showScope);
  base.addEventListener("input", showScope);
  showScope();
}

const policy = find("#scan-policy");
if (policy && matchMedia("(min-width: 961px)").matches) policy.open = true;

const lock = find('[name="lock"]');
if (lock) {
  function countBytes() {
    const count = new TextEncoder().encode(lock.value).length;
    const message = count > 262144 ? "Cargo.lock exceeds 262,144 bytes" : "";
    find("#lock-count").textContent = message || count.toLocaleString("en-US") + " / 262,144 bytes";
    lock.setCustomValidity(message);
  }
  lock.addEventListener("input", countBytes);
  countBytes();
}

for (const button of document.querySelectorAll("[data-copy]")) {
  if (!navigator.clipboard) continue;
  button.hidden = false;
  button.addEventListener("click", async () => {
    const code = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(code.textContent);
      find("#copy-status").textContent = "Copied";
    } catch {
      find("#copy-status").textContent = "Select the value and copy it manually.";
    }
  });
}

const filters = find(".filters");
if (filters) {
  const entries = [...document.querySelectorAll(".catalog-entry")];
  const search = find("#rule-search");
  const category = find("#category");
  const method = find("#method");
  for (const select of [category, method]) {
    const values = new Set(entries.map(entry => entry.dataset[select.id]));
    for (const value of values) select.add(new Option(value, value));
  }
  function filter() {
    const query = search.value.trim().toLowerCase();
    let visible = 0;
    for (const entry of entries) {
      const {id, name, category: group, method: type} = entry.dataset;
      entry.hidden = !(id + " " + name).toLowerCase().includes(query)
        || Boolean(category.value && group !== category.value)
        || Boolean(method.value && type !== method.value);
      if (!entry.hidden) visible++;
    }
    find("#no-rules").hidden = visible > 0;
  }
  filters.hidden = false;
  filters.addEventListener("input", filter);
  find("#no-rules button").addEventListener("click", () => {
    search.value = category.value = method.value = "";
    filter();
    search.focus();
  });
}
const sections = find(".sections");
sections?.addEventListener("focusin", event => {
  event.target.scrollIntoView({block: "nearest", inline: "nearest", behavior: "instant"});
});
function selectSection() {
  const hash = location.hash || "#overview";
  for (const link of document.querySelectorAll(".sections a")) {
    if (link.hash === hash) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  }
  const target = document.getElementById(hash.slice(1));
  const rule = target?.closest("details.result");
  if (rule) rule.open = true;
}
window.addEventListener("hashchange", selectSection);
selectSection();

const printButton = find("[data-print]");
if (printButton) {
  printButton.hidden = false;
  printButton.addEventListener("click", () => window.print());
}

// Restore the reader's disclosures after the browser has laid out the paper copy.
let closedForScreen = [];
window.addEventListener("beforeprint", () => {
  closedForScreen = [...document.querySelectorAll(".report-shell details:not([open]):not(.no-print)")];
  for (const disclosure of closedForScreen) disclosure.open = true;
});
window.addEventListener("afterprint", () => {
  for (const disclosure of closedForScreen) disclosure.open = false;
  closedForScreen = [];
});
