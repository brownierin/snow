package com.mycompany.test;

public class Test {
    public static void unsafe() {
        Random rnd = new Random();
        rnd.nextLong();
    }
}
