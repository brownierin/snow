var fnct = new Function("return test();");
fnct();

var fnct2 = new Function("a,b", "return test();");
fnct2();