package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        JsonParser jsonParser = new JsonParser()
            .setClassMetadataName("class");
        
        return jsonParser.parse(value, Object.class);
    }

    public static Object unsafe2(String value) {
        JsonParser jsonParser = new JsonParser();
        jsonParser = jsonParser.setClassMetadataName("class");
        return jsonParser.parse(value, Object.class);
    }

    public static Object unsafe3(String value) {
        JsonParser jsonParser = new JsonParser();
        return jsonParser.setClassMetadataName("class").parse(value, Object.class);
    }

    public static Object safe(String value) {
        JsonParser jsonParser = new JsonParser();
        return jsonParser.parse(value, Object.class);
    }
}
