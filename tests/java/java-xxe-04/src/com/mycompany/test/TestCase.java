package com.mycompany.test;

public class Test {
    public static void main(String...args) {
        SAXParserFactory spf = SAXParserFactory.newInstance();
        SAXParser parser = spf.newSAXParser();
        XMLReader xmlReader = parser.getXMLReader();
        xmlReader.parse(null);
    }

    public static void foobar() {
        SAXParserFactory spf2 = SAXParserFactory.newInstance();
        spf2.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        SAXParser parser2 = spf2.newSAXParser();
        XMLReader xmlReader2 = parser2.getXMLReader();
        xmlReader2.parse(null);
    }

    public static void barfoo() {
        SAXParserFactory spf3 = SAXParserFactory.newInstance();
        SAXParser parser3 = spf3.newSAXParser();
        XMLReader xmlReader3 = parser3.getXMLReader();
        xmlReader3.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        xmlReader3.parse(null);
    }
}