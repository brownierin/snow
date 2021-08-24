package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        JSONDeserializer jsonDeserializer = new JSONDeserializer();
        return jsonDeserializer.deserialize(value);
    }
}
