package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        Kryo kryo = new Kryo();
        ByteArrayInputStream bais = new ByteArrayInputStream(value.getBytes());
        Input input = new Input(bais);
        return kryo.readObject(input, Object.class);
    }

    public static Object unsafe2(String value) {
        Input input = new Input(value.getBytes());
        Kryo kryo = new Kryo();
        Object obj = kryo.readObject(input, Object.class);
        return obj;
    }

    public static Object safe() {
        Kryo kryo = new Kryo();
        Input input = new Input(new FileInputStream("config.xml"));
        return kryo.readObject(input, Object.class);
    }
}
