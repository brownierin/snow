package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        return JsonReader.jsonToJava(value);
    }
}
