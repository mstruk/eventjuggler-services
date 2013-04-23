package org.gatein.security.oauth.im;

/**
 * @author <a href="mailto:marko.strukelj@gmail.com">Marko Strukelj</a>
 */
public class OrganizationService {

    private UserHandler userHandler;
    private UserProfileHandler userProfileHandler;

    public UserHandler getUserHandler() {
        return userHandler;
    }

    public UserProfileHandler getUserProfileHandler() {
        return userProfileHandler;
    }
}
