package com.mycompany.test;

public class Test {
    public static void unsafe() {
        Cipher.getInstance("DES/CBC/PKCS5Padding");
    }
}
