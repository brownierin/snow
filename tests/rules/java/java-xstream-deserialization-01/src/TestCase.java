package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        XStream xstream = new XStream(new DomDriver());
        return xstream.fromXML(value);
    }

    public static Object unsafe2() {
        XStream xstream = new XStream(new DomDriver());
        String v = SomeClass.LoadFromSomehwere();
        return xstream.fromXML(v);
    }

    public static Object unsafe3() {
        String v = SomeClass.LoadFromSomehwere();
        ByteArrayInputStream bais = new ByteArrayInputStream(v.getBytes());
        XStream xstream = new XStream(new DomDriver());
        return xstream.fromXML(bais);
    }

    public static Object safe() {
        XStream xstream = new XStream(new DomDriver());
        return xstream.fromXML(new FileInputStream("config.xml"));
    }
}
