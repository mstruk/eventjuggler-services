package org.eventjuggler.services.idb.provider;

import java.util.Collections;
import java.util.Map;
import java.util.HashMap;

public class IdentityProviderState {

    private final Map<String, Object> state = Collections.synchronizedMap(new HashMap<String, Object>());

    public boolean contains(String key) {
        return state.containsKey(key);
    }

    @SuppressWarnings("unchecked")
    public <T> T remove(String key) {
        return (T) state.remove(key);
    }

    public void put(String key, Object value) {
        state.put(key, value);
    }

}
