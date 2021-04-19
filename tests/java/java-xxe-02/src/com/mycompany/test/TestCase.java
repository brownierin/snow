package com.mycompany.test;

public class Test {
    public static void main(String...args) {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        parser.parse(null, null);
    }

    public static void foobar() {
        SAXParserFactory spf2 = SAXParserFactory.newInstance();
        spf2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        SAXParser parser = spf2.newSAXParser();
        parser.parse(null, null);
    }
}