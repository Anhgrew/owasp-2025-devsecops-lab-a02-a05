import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const source = fs.readFileSync(new URL("./dist/app.js", import.meta.url), "utf8");
const html = fs.readFileSync(new URL("./dist/index.html", import.meta.url), "utf8");
const expectedIds = ["misconfig-debug", "kubernetes", "sql-injection", "command-injection", "nosql-injection"];

class ClassList {
  constructor(initial = []) { this.values = new Set(initial); }
  add(...names) { names.forEach(name => this.values.add(name)); }
  remove(...names) { names.forEach(name => this.values.delete(name)); }
  toggle(name, force) {
    if (force === true) this.values.add(name);
    else if (force === false) this.values.delete(name);
    else if (this.values.has(name)) this.values.delete(name);
    else this.values.add(name);
    return this.values.has(name);
  }
  contains(name) { return this.values.has(name); }
}

class Element {
  constructor(id = "") {
    this.id = id;
    this.dataset = {};
    this.style = { setProperty() {} };
    this.classList = new ClassList();
    this.listeners = new Map();
    this.textContent = "";
    this.innerHTML = "";
    this.value = "";
    this.disabled = false;
  }
  addEventListener(type, handler) {
    const handlers = this.listeners.get(type) || [];
    handlers.push(handler);
    this.listeners.set(type, handlers);
  }
  click() { (this.listeners.get("click") || []).forEach(handler => handler({ currentTarget: this, preventDefault() {} })); }
  setAttribute() {}
  focus() {}
  showModal() {}
  querySelector() { return new Element("child"); }
}

const elements = new Map();
const element = id => {
  if (!elements.has(id)) elements.set(id, new Element(id));
  return elements.get(id);
};

const panels = Object.fromEntries(["overview", "a02", "a05", "pipeline", "labs", "references", "lab-workspace"].map(name => {
  const panel = new Element(`view-${name}`);
  panel.dataset.viewPanel = name;
  return [name, panel];
}));
const launchButtons = expectedIds.map(id => {
  const button = new Element(`launch-${id}`);
  button.dataset.launchLab = id;
  return button;
});

const storage = new Map();
const location = { hash: "" };
const document = {
  activeElement: null,
  getElementById: element,
  addEventListener() {},
  querySelector(selector) {
    const match = selector.match(/^\[data-view-panel="(.+)"\]$/);
    return match ? panels[match[1]] || null : null;
  },
  querySelectorAll(selector) {
    if (selector === "[data-view-panel]") return Object.values(panels);
    if (selector === "[data-launch-lab]") return launchButtons;
    return [];
  }
};
const context = {
  console,
  document,
  location,
  history: { replaceState(_a, _b, hash) { location.hash = hash; } },
  localStorage: {
    getItem(key) { return storage.get(key) || null; },
    setItem(key, value) { storage.set(key, value); }
  },
  window: { scrollTo() {}, addEventListener() {} },
  setTimeout,
  clearTimeout
};

vm.createContext(context);
vm.runInContext(`${source}\n;var __labTest = { ids: Object.keys(labs), route: initialRoute, setStep(n) { currentStep = n; renderLab(); } };`, context);

assert.deepEqual([...context.__labTest.ids], expectedIds, "The app must register the intended five labs in order");
const stepMarkers = ["mission-map", "runAttack", "evidence-timeline", "code-diff", "applyDefense", "runTests", "quiz-question"];
for (const id of expectedIds) {
  assert.match(html, new RegExp(`data-launch-lab="${id}"`), `Missing launch control for ${id}`);
  launchButtons.find(button => button.dataset.launchLab === id).click();
  assert.equal(location.hash, `#lab/${id}`, `${id} should create a deep link`);
  assert.equal(panels["lab-workspace"].classList.contains("active"), true, `${id} should activate the workspace panel`);
  location.hash = `#lab/${id}`;
  context.__labTest.route();
  assert.equal(panels["lab-workspace"].classList.contains("active"), true, `${id} should reopen from its deep link`);
  for (let step = 0; step < 7; step += 1) {
    context.__labTest.setStep(step);
    assert.match(element("labWorkspace").innerHTML, /FACILITATOR CUE/, `${id} step ${step + 1} should include facilitator guidance`);
    assert.match(element("labWorkspace").innerHTML, new RegExp(labsTitlePattern(id)), `${id} step ${step + 1} should render its title`);
    assert.match(element("labWorkspace").innerHTML, new RegExp(stepMarkers[step]), `${id} step ${step + 1} should render its interactive surface`);
  }
}

function labsTitlePattern(id) {
  return ({
    "misconfig-debug": "Production Debug Leak",
    kubernetes: "Kubernetes Service Account Overreach",
    "sql-injection": "SQL Injection",
    "command-injection": "OS Command Injection",
    "nosql-injection": "NoSQL Operator Injection"
  })[id];
}

console.log("PASS: five launch buttons open the correct workspace and all 35 lab steps render");
