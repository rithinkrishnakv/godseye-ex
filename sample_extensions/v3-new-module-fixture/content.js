// Context leakage
window.extensionAPI = chrome.storage;

const event = new CustomEvent("ext-data", {detail: chrome.runtime.id});
document.dispatchEvent(event);

window.postMessage({data: chrome.storage.local}, "*");

const s = document.createElement("script");
s.src = "data:text/javascript,alert(1)";
document.head.appendChild(s);
