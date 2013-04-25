package org.eventjuggler.services.idb.provider;

import javax.enterprise.context.SessionScoped;
import java.util.UUID;

/**
 * @author <a href="mailto:marko.strukelj@gmail.com">Marko Strukelj</a>
 */
@SessionScoped
class Session {

    private String code;

    private String accessToken;

    private String state = UUID.randomUUID().toString();

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getState() {
        return state;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }
}
