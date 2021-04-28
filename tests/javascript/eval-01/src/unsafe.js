setTimeout("callMe()", 1000);

var code = "callMe();" + otherCode;
setTimeout(code, 1000);

var code2 = "callMe();";
setInterval(code2, 1000);