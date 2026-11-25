"use strict";

const find = selector => document.querySelector(selector);
for (const options of document.querySelectorAll(".scan-options")) {
  options.addEventListener("invalid", () => { options.open = true; }, true);
}

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
    const labels = {A: "A · Direct evidence", S: "S · Source analysis", E: "E · Manual review", X: "X · Extension"};
    for (const value of values) {
      select.add(new Option(select === method ? labels[value] ?? value : value, value));
    }
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
function followFragment() {
  const hash = location.hash;
  if (hash === "#create") {
    const create = find(".create-project");
    if (create) create.open = true;
  }
  const sections = find(".sections");
  if (sections && !location.search && ["#scan", "#members", "#history"].includes(hash)) {
    const destination = hash === "#scan"
      ? sections.querySelector("[data-work-section]")
      : sections.querySelector(`[href$="?section=${hash.slice(1)}"]`);
    if (destination && !destination.hasAttribute("aria-current")) location.replace(destination.href);
  }
  const links = sections?.querySelectorAll('a[href^="#"]');
  for (const link of links ?? []) {
    if (link.hash === (hash || links[0].hash)) link.setAttribute("aria-current", "location");
    else link.removeAttribute("aria-current");
  }
  const target = document.getElementById(hash.slice(1));
  const rule = target?.closest("details.result");
  if (rule) rule.open = true;
}
window.addEventListener("hashchange", followFragment);
followFragment();

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
