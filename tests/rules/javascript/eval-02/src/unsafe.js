var dynamicCode = "test();";
dynamicCode += yay;

var fnct = new Function(dynamicCode);
fnct();


var dynamicCode2 = "test();";
dynamicCode2 += yay2;

var fnct2 = new Function("a,b", dynamicCode);
fnct2();