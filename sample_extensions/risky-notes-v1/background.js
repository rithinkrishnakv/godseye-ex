const apiKey = "AKIAABCDEFGHIJKLMNOP";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  chrome.storage.local.set({ password: msg.password });
});
