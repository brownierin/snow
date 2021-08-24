package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        AMFConnection amfConnection = new AMFConnection();
        amfConnection.connect("https://example.org/messagebroker/amf");
        return amfConnection.call("remoting_AMF.yay", "yay");
    }
}
