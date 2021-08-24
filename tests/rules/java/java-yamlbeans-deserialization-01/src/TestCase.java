package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        YamlReader reader = new YamlReader(new StringReader(value));
        Object object = reader.read();
        return object;
    }
}
