package com.mycompany.test;

import org.apache.http.impl.client.DefaultHttpClient;

public class Test {
    public static void unsafe() {
        HttpClient client = new DefaultHttpClient();
    }
}
