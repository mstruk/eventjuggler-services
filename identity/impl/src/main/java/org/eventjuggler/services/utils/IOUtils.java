package org.eventjuggler.services.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:marko.strukelj@gmail.com">Marko Strukelj</a>
 */
public class IOUtils {

    public static final int BUF_SIZE = 8192;


    public static final long copyWithDefaultLimit(InputStream is, OutputStream os) throws IOException {
        return copyWithLimit(is, os, BUF_SIZE);
    }

    public static final long copyWithLimit(InputStream is, OutputStream os, int limit) throws IOException {

        byte [] buf = new byte[BUF_SIZE];
        int count = 0;

        try {
            int rc = is.read(buf);
            while (rc != -1) {
                os.write(buf, 0, rc);
                count+=rc;
                if (count > limit)
                    throw new IOException("Limit exceeded: " + limit);

                rc = is.read(buf);
            }
        } finally {
            try {
                is.close();
            } catch(Exception ignored) {}

            os.close();
        }

        return count;
    }

    /**
     * Decode given String to map. For example for input: accessToken=123456&expires=20071458 it returns map with two keys
     * "accessToken" and "expires" and their corresponding values
     *
     * @param encodedData
     * @return map with output data
     */
    public static Map<String, String> formUrlDecode(String encodedData) {
        Map<String, String> params = new HashMap<String, String>();
        String[] elements = encodedData.split("&");
        for (String element : elements) {
            String[] pair = element.split("=");
            if (pair.length == 2) {
                String paramName = pair[0];
                String paramValue;
                try {
                    paramValue = URLDecoder.decode(pair[1], "UTF-8");
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException(e);
                }
                params.put(paramName, paramValue);
            } else {
                throw new RuntimeException("Unexpected name-value pair in response: " + element);
            }
        }
        return params;
    }
}
