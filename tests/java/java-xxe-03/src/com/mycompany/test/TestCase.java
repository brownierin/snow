package com.mycompany.test;

public class Test {
    public static void main(String...args) {
        SAXReader reader = new SAXReader();
        reader.read(new InputSource(new StringReader("...")));
    }

    public static void foobar() {
        SAXReader reader2 = new SAXReader();
        reader2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        reader2.read(new InputSource(new StringReader("...")));
    }
}