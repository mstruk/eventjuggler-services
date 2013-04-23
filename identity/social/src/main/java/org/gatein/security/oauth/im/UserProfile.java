package org.gatein.security.oauth.im;

import java.util.HashMap;
import java.util.Map;

/**
 * @author <a href="mailto:marko.strukelj@gmail.com">Marko Strukelj</a>
 */
public class UserProfile {

    private Map<String, String> attrs = new HashMap<String, String>();
    private String userId;

    public void setAttribute(String key, String value) {
        attrs.put(key, value);
    }

    public String getAttribute(String key) {
        return attrs.get(key);
    }

    public String getUserId() {
        return userId;
    }
}
