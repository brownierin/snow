package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        Genson genson = new GensonBuilder()
            .useRuntimeType(true)
            .create();
        
        return genson.deserialize(value, Object.class);
    }
}
