function messageReceiver(message, sender, sendResponse) {
    if (sender.id != "yay") {
        return;
    }
    
    doSomething(message);
}

chrome.runtime.onMessageExternal.addListener(function (message, sender, sendResponse) {
    if (sender.id == "bob") {
        doSomething(message);
    }
});

chrome.runtime.onMessageExternal.addListener(messageReceiver);