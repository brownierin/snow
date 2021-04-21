package com.mycompany.test;

public class Test {
    public static void unsafe() {
        ObjectMapper om = new ObjectMapper();
        om.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE, JsonTypeInfo.As.PROPERTY);
        om.readObject("{}", Object.class);
    }
}
