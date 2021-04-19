package com.mycompany.test;

public class Test {
    public static void main(String...args) {
        SAXBuilder builder = new SAXBuilder();
        builder.build(null);
    }

    public static void foobar() {
        SAXBuilder builder2 = new SAXBuilder();
        builder2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        builder2.build(null);
    }
}