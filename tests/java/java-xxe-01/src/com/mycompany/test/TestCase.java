package com.mycompany.test;

public class Test {
    public static void main(String...args) {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder unsafeBuilder = dbf.newDocumentBuilder();
    }

    public static void foobar() {
        DocumentBuilderFactory dbf2 = DocumentBuilderFactory.newInstance();
        dbf2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder safeBuilder = dbf2.newDocumentBuilder();
    }
}