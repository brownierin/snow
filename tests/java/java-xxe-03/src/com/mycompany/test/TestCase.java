package com.mycompany.test;

public class Test {
    public static void unsafe() {
        SAXReader reader = new SAXReader();
        reader.read(new InputSource(new StringReader("...")));
    }

    public static void safe() {
        SAXReader reader2 = new SAXReader();
        reader2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader2.read(new InputSource(new StringReader("...")));
    }
}
