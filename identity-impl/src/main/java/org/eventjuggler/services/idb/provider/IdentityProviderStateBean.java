package org.eventjuggler.services.idb.provider;

import java.util.HashMap;
import java.util.Map;

import javax.ejb.Singleton;

@Singleton
public class IdentityProviderStateBean {

    private final Map<String, IdentityProviderState> states = new HashMap<>();

    public synchronized IdentityProviderState getState(IdentityProvider provider) {
        IdentityProviderState s = states.get(provider.getId());
        if (s == null) {
            s = new IdentityProviderState();
            states.put(provider.getId(), s);
        }
        return s;
    }

}
