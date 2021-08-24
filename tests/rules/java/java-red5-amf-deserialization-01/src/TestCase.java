package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        Inporg.red5.io.amf.Input input = new org.red5.io.amf.Input(new ByteArrayInputStream(value.getBytes()));
        String action = Deserializer.deserialize(input, String.class);
        return action;
    }
}
