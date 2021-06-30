package com.mycompany.test;

public class Test {
    public static void unsafe() {
        ObjectMapper om = new ObjectMapper();
        om.enableDefaultTyping(ObjectMapper.DefaultTyping.OBJECT_AND_NON_CONCRETE, JsonTypeInfo.As.PROPERTY);
        om.readObject("{}", Object.class);
    }

    public static void unsafe2() {
        ObjectMapper om = new ObjectMapper();
        TypeResolverBuilder<?> typeResolver = new CustomTypeResolverBuilder();
        om.setDefaultTyping(typeResolver);
        om.readObject("{}", Object.class);
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "className")
    public abstract class MyUnsafeObject {

    }

    @JsonTypeInfo(property = "class", use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY)
    @JsonSubTypes({
            @JsonSubTypes.Type(value=String.class, name="classA"),
            @JsonSubTypes.Type(value=Integer.class, name="classB")
    })
    public abstract class MySafeObject {

    }
}
