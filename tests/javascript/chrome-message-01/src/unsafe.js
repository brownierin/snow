function messageReceiver(message, sender, sendResponse) {
    doSomething(message);
}

chrome.runtime.onMessageExternal.addListener(function (message, sender, sendResponse) {
    doSomething(message);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    doSomething(message);
});

chrome.runtime.onMessageExternal.addListener(messageReceiver);