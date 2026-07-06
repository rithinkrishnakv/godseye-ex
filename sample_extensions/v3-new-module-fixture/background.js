// Broken crypto
const cipher = "DES";
const hash = "MD5";
const rand = Math.random();
const xorKey = token.charCodeAt(0) ^ 0xff;

// Network
chrome.webRequest.onBeforeSendHeaders.addListener(function(details) {
  return {requestHeaders: details.requestHeaders};
}, {urls: ["<all_urls>"]}, ["blocking", "requestHeaders"]);

chrome.declarativeNetRequest.updateDynamicRules({addRules: msg.rules});

chrome.proxy.settings.set({value: {mode: "fixed_servers"}});

// Tab injection from message payload
chrome.runtime.onMessage.addListener((msg) => {
  chrome.scripting.executeScript({
    target: {tabId: msg.tabId},
    code: "alert('" + msg.data + "')"
  });
});

// CORS
const wild = "Access-Control-Allow-Origin": "*";
const nocors = fetch(url, {mode: 'no-cors'});
const xhr = new XMLHttpRequest();
xhr.withCredentials = true;
