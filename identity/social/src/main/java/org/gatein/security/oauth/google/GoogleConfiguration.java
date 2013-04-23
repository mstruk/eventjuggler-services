package org.gatein.security.oauth.google;

import org.gatein.security.oauth.common.SocialServiceConfiguration;

/**
 * @author <a href="mailto:marko.strukelj@gmail.com">Marko Strukelj</a>
 */
public class GoogleConfiguration extends SocialServiceConfiguration {

    private String accessType;
    private String applicationName;

    public String getAccessType() {
        return accessType;
    }

    public void setAccessType(String accessType) {
        this.accessType = accessType;
    }

    public String getApplicationName() {
        return applicationName;
    }

    public void setApplicationName(String applicationName) {
        this.applicationName = applicationName;
    }
}
