package com.mycompany.test;

public class Test {
    public static Object unsafe(String value) {
        StringReader read = new StringReader(value);
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        return jaxbUnmarshaller.unmarshal(read);
    }

    public static Object unsafe2(String value) {
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        return jaxbUnmarshaller.unmarshal(new ByteArrayInputStream(value.getBytes()));
    }

    public static Object safe() {
        Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
        return jaxbUnmarshaller.unmarshal(new FileInputStream("config.xml"));
    }
}
