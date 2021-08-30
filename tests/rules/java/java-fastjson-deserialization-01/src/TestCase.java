package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        return JSON.parseObject(value, Object.class);
    }
}
