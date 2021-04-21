package com.mycompany.test;

public class Test {
    public static void unsafe(String...args) {
        byte b[] = serializedObject.getBytes(); 
        ByteArrayInputStream bi = new ByteArrayInputStream(b);
        ObjectInputStream si = new ObjectInputStream(bi);
        MyObject obj = (MyObject) si.readObject();
    }
}
