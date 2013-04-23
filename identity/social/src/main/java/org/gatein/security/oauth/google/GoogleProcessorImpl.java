/*
 * JBoss, a division of Red Hat
 * Copyright 2013, Red Hat Middleware, LLC, and individual
 * contributors as indicated by the @authors tag. See the
 * copyright.txt in the distribution for a full listing of
 * individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.gatein.security.oauth.google;

import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeRequestUrl;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleCredential;
import com.google.api.client.googleapis.auth.oauth2.GoogleRefreshTokenRequest;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.HttpResponseException;
import com.google.api.client.http.HttpTransport;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson.JacksonFactory;
import com.google.api.services.oauth2.Oauth2;
import com.google.api.services.oauth2.model.Tokeninfo;
import com.google.api.services.oauth2.model.Userinfo;
import com.google.api.services.plus.Plus;
import org.gatein.security.oauth.common.InteractionState;
import org.gatein.security.oauth.common.OAuthCodec;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.exception.OAuthException;
import org.gatein.security.oauth.exception.OAuthExceptionCode;
import org.gatein.security.oauth.im.UserProfile;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class GoogleProcessorImpl implements GoogleProcessor {

    private static Logger log = Logger.getLogger(GoogleProcessorImpl.class.getName());

    private final String redirectUrl;
    private final String clientID;
    private final String clientSecret;
    private final Set<String> scopes = new HashSet<String>();
    private final String accessType;
    private final String applicationName;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Default HTTP transport to use to make HTTP requests.
     */
    private final HttpTransport TRANSPORT = new NetHttpTransport();

    /**
     * Default JSON factory to use to deserialize JSON.
     */
    private final JacksonFactory JSON_FACTORY = new JacksonFactory();

    // Only for unit test purpose
    public GoogleProcessorImpl() {
        this.redirectUrl = null;
        this.clientID = null;
        this.clientSecret = null;
        this.accessType = null;
        this.applicationName = null;
    }

    public GoogleProcessorImpl(GoogleConfiguration conf) {
        this.clientID = conf.getClientId();
        this.clientSecret = conf.getClientSecret();
        this.redirectUrl = conf.getRedirectUrl();
        String scope = conf.getScope();

        this.accessType = conf.getAccessType();
        this.applicationName = conf.getApplicationName();

        if (clientID == null || clientID.length() == 0 || clientID.trim().equals("<<to be replaced>>")) {
            throw new IllegalArgumentException("Property 'clientId' needs to be provided. The value should be " +
                    "clientId of your Google application");
        }

        if (clientSecret == null || clientSecret.length() == 0 || clientSecret.trim().equals("<<to be replaced>>")) {
            throw new IllegalArgumentException("Property 'clientSecret' needs to be provided. The value should be " +
                    "clientSecret of your Google application");
        }

        if (redirectUrl == null || redirectUrl.length() == 0) {
            throw new IllegalArgumentException("Property 'redirectUrl' needs to be provided.");
        }

        if (applicationName == null || applicationName.length() == 0) {
            throw new IllegalArgumentException("Property 'applicationName' needs to be provided.");
        }

        addScopesFromString(scope, this.scopes);

        log.fine("configuration: clientId=" + clientID +
            ", clientSecret=" + clientSecret +
            ", redirectUrl=" + redirectUrl +
            ", scope=" + scopes +
            ", accessType=" + accessType +
            ", applicationName=" + applicationName);
    }

    @Override
    public InteractionState<GoogleAccessTokenContext> processOAuthInteraction(HttpServletRequest httpRequest, HttpServletResponse httpResponse) throws IOException, OAuthException {
        return processOAuthInteractionImpl(httpRequest, httpResponse, this.scopes);
    }

    @Override
    public InteractionState<GoogleAccessTokenContext> processOAuthInteraction(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String scope) throws IOException, OAuthException {
        Set<String> scopes = new HashSet<String>();
        addScopesFromString(scope, scopes);
        return processOAuthInteractionImpl(httpRequest, httpResponse, scopes);
    }

    protected InteractionState<GoogleAccessTokenContext> processOAuthInteractionImpl(HttpServletRequest request, HttpServletResponse response, Set<String> scopes)
            throws IOException {
        HttpSession session = request.getSession();
        String state = (String) session.getAttribute(OAuthConstants.ATTRIBUTE_AUTH_STATE);

        // Very initial request to portal
        if (state == null || state.isEmpty()) {

            return initialInteraction(request, response, scopes);
        } else if (state.equals(InteractionState.State.AUTH.name())) {
            GoogleTokenResponse tokenResponse = obtainAccessToken(request);
            GoogleAccessTokenContext accessTokenContext = validateTokenAndUpdateScopes(tokenResponse);

            // Clear session attributes
            session.removeAttribute(OAuthConstants.ATTRIBUTE_AUTH_STATE);
            session.removeAttribute(OAuthConstants.ATTRIBUTE_VERIFICATION_STATE);

            return new InteractionState<GoogleAccessTokenContext>(InteractionState.State.FINISH, accessTokenContext);
        }

        // Likely shouldn't happen...
        return new InteractionState<GoogleAccessTokenContext>(InteractionState.State.valueOf(state), null);
    }

    protected InteractionState<GoogleAccessTokenContext> initialInteraction(HttpServletRequest request, HttpServletResponse response, Set<String> scopes) throws IOException {
        String verificationState = String.valueOf(secureRandom.nextLong());
        String authorizeUrl = new GoogleAuthorizationCodeRequestUrl(clientID, redirectUrl, scopes).
                setState(verificationState).setAccessType(accessType).build();
        if (log.isLoggable(Level.FINEST)) {
            log.finest("Starting OAuth2 interaction with Google+");
            log.finest("URL to send to Google+: " + authorizeUrl);
        }

        HttpSession session = request.getSession();
        session.setAttribute(OAuthConstants.ATTRIBUTE_VERIFICATION_STATE, verificationState);
        session.setAttribute(OAuthConstants.ATTRIBUTE_AUTH_STATE, InteractionState.State.AUTH.name());
        response.sendRedirect(authorizeUrl);
        return new InteractionState<GoogleAccessTokenContext>(InteractionState.State.AUTH, null);
    }

    protected GoogleTokenResponse obtainAccessToken(HttpServletRequest request) throws IOException {
        HttpSession session = request.getSession();
        String stateFromSession = (String)session.getAttribute(OAuthConstants.ATTRIBUTE_VERIFICATION_STATE);
        String stateFromRequest = request.getParameter(OAuthConstants.STATE_PARAMETER);
        if (stateFromSession == null || stateFromRequest == null || !stateFromSession.equals(stateFromRequest)) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_INVALID_STATE, "Validation of state parameter failed. stateFromSession="
                    + stateFromSession + ", stateFromRequest=" + stateFromRequest);
        }

        String code = request.getParameter(OAuthConstants.CODE_PARAMETER);

        GoogleTokenResponse tokenResponse = new GoogleAuthorizationCodeTokenRequest(TRANSPORT, JSON_FACTORY, clientID,
                clientSecret, code, redirectUrl).execute();

        if (log.isLoggable(Level.FINEST)) {
            log.finest("Successfully obtained accessToken from google: " + tokenResponse);
        }

        return tokenResponse;
    }


    @Override
    public GoogleAccessTokenContext validateTokenAndUpdateScopes(GoogleAccessTokenContext accessTokenContext) {
        return this.validateTokenAndUpdateScopes(accessTokenContext.getTokenData());
    }

    protected GoogleAccessTokenContext validateTokenAndUpdateScopes(GoogleTokenResponse tokenResponse) {
        Oauth2 oauth2 = getOAuth2InstanceImpl(tokenResponse);
        GoogleCredential credential = getGoogleCredential(tokenResponse);

        Tokeninfo tokenInfo;
        try {
            tokenInfo = oauth2.tokeninfo().setAccessToken(credential.getAccessToken()).execute();
        } catch (IOException ioe) {
            // TODO: handle separately the case with bad access token and with network error
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_GOOGLE_ERROR, "Error when obtaining tokenInfo");
        }

        // If there was an error in the token info, abort.
        if (tokenInfo.containsKey("error")) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_GOOGLE_ERROR, "Error during token validation: " + tokenInfo.get("error").toString());
        }

        if (!tokenInfo.getIssuedTo().equals(clientID)) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_GOOGLE_ERROR, "Token's client ID does not match app's. clientID from tokenINFO: " + tokenInfo.getIssuedTo());
        }

        if (log.isLoggable(Level.FINEST)) {
            log.finest("Successfully validated accessToken from google: " + tokenInfo);
        }

        String[] scopes = tokenInfo.getScope().split(" ");
        return new GoogleAccessTokenContext(tokenResponse, scopes);
    }


    @Override
    public Userinfo obtainUserInfo(GoogleAccessTokenContext accessTokenContext) {
        Oauth2 oauth2 = getOAuth2Instance(accessTokenContext);
        Userinfo uinfo;
        try {
            uinfo = oauth2.userinfo().v2().me().get().execute();
        } catch (IOException ioe) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_GOOGLE_ERROR, "Error when obtaining User Info");
        }

        if (log.isLoggable(Level.FINEST)) {
            log.finest("Successfully obtained userInfo from google: " + uinfo);
        }

        return uinfo;
    }

    @Override
    public Oauth2 getOAuth2Instance(GoogleAccessTokenContext accessTokenContext) {
        GoogleTokenResponse tokenData = accessTokenContext.getTokenData();
        return getOAuth2InstanceImpl(tokenData);
    }

    protected Oauth2 getOAuth2InstanceImpl(GoogleTokenResponse tokenData) {
        GoogleCredential credential = getGoogleCredential(tokenData);
        return new Oauth2.Builder(TRANSPORT, JSON_FACTORY, credential).setApplicationName(applicationName).build();
    }

    @Override
    public Plus getPlusService(GoogleAccessTokenContext accessTokenContext) {
        GoogleTokenResponse tokenData = accessTokenContext.getTokenData();
        // Build credential from stored token data.
        GoogleCredential credential = getGoogleCredential(tokenData);

        // Create a new authorized API client.
        Plus service = new Plus.Builder(TRANSPORT, JSON_FACTORY, credential)
                .setApplicationName(applicationName)
                .build();
        return service;
    }

    private GoogleCredential getGoogleCredential(GoogleTokenResponse tokenResponse) {
        return new GoogleCredential.Builder()
                .setJsonFactory(JSON_FACTORY)
                .setTransport(TRANSPORT)
                .setClientSecrets(clientID, clientSecret).build()
                .setFromTokenResponse(tokenResponse);
    }

    @Override
    public void saveAccessTokenAttributesToUserProfile(UserProfile userProfile, OAuthCodec codec, GoogleAccessTokenContext accessToken) {
        GoogleTokenResponse tokenData = accessToken.getTokenData();
        String encodedAccessToken = codec.encodeString(tokenData.getAccessToken());
        String encodedRefreshToken = codec.encodeString(tokenData.getRefreshToken());
        String encodedScope = codec.encodeString(accessToken.getScopesAsString());
        userProfile.setAttribute(OAuthConstants.PROFILE_GOOGLE_ACCESS_TOKEN, encodedAccessToken);
        userProfile.setAttribute(OAuthConstants.PROFILE_GOOGLE_SCOPE, encodedScope);

        // Don't overwrite existing refresh token because it's not present in every accessToken response (only in very first one)
        if (encodedRefreshToken != null) {
            userProfile.setAttribute(OAuthConstants.PROFILE_GOOGLE_REFRESH_TOKEN, encodedRefreshToken);
        }
    }

    @Override
    public GoogleAccessTokenContext getAccessTokenFromUserProfile(UserProfile userProfile, OAuthCodec codec) {
        String decodedAccessToken = codec.decodeString(userProfile.getAttribute(OAuthConstants.PROFILE_GOOGLE_ACCESS_TOKEN));

        // We don't have token in userProfile
        if (decodedAccessToken == null) {
            return null;
        }

        String decodedRefreshToken = codec.decodeString(userProfile.getAttribute(OAuthConstants.PROFILE_GOOGLE_REFRESH_TOKEN));
        String decodedScope = codec.decodeString(userProfile.getAttribute(OAuthConstants.PROFILE_GOOGLE_SCOPE));
        GoogleTokenResponse grc = new GoogleTokenResponse();
        grc.setAccessToken(decodedAccessToken);
        grc.setRefreshToken(decodedRefreshToken);
        grc.setTokenType("Bearer");
        grc.setExpiresInSeconds(1000L);
        grc.setIdToken("someTokenId");
        return new GoogleAccessTokenContext(grc, decodedScope);
    }

    @Override
    public void removeAccessTokenFromUserProfile(UserProfile userProfile) {
        userProfile.setAttribute(OAuthConstants.PROFILE_GOOGLE_ACCESS_TOKEN, null);
        userProfile.setAttribute(OAuthConstants.PROFILE_GOOGLE_REFRESH_TOKEN, null);
        userProfile.setAttribute(OAuthConstants.PROFILE_GOOGLE_SCOPE, null);
    }

    @Override
    public void revokeToken(GoogleAccessTokenContext accessTokenContext) throws OAuthException
    {
        GoogleTokenResponse tokenData = accessTokenContext.getTokenData();

        try {
            revokeTokenImpl(tokenData);
        } catch (IOException ioe) {
            if (ioe instanceof HttpResponseException) {
                HttpResponseException googleException = (HttpResponseException)ioe;
                if (googleException.getStatusCode() == 400 && googleException.getContent().contains("invalid_token") && tokenData.getRefreshToken() != null) {
                    try {
                        // Refresh token and retry revocation with refreshed token
                        refreshToken(accessTokenContext);
                        revokeTokenImpl(tokenData);
                        return;
                    } catch (OAuthException refreshException) {
                        // Log this one with trace level. We will rethrow original exception
                        if (log.isLoggable(Level.FINEST)) {
                            log.log(Level.FINEST, "Refreshing token failed", refreshException);
                        }
                    } catch (IOException ioe2) {
                        ioe = ioe2;
                    }
                }
            }
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_TOKEN_REVOKE_FAILED, "Error when revoking token", ioe);
        }
    }

    // Send request to google without any exception handling.
    private void revokeTokenImpl(GoogleTokenResponse tokenData) throws IOException {
        TRANSPORT.createRequestFactory()
                .buildGetRequest(new GenericUrl("https://accounts.google.com/o/oauth2/revoke?token=" + tokenData.getAccessToken())).execute();
        if (log.isLoggable(Level.FINEST)) {
            log.finest("Revoked token " + tokenData);
        }
    }

    @Override
    public void refreshToken(GoogleAccessTokenContext accessTokenContext) {
        GoogleTokenResponse tokenData = accessTokenContext.getTokenData();
        if (tokenData.getRefreshToken() == null) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_GOOGLE_ERROR, "Given GoogleTokenResponse does not contain refreshToken");
        }

        try {
            GoogleRefreshTokenRequest refreshTokenRequest = new GoogleRefreshTokenRequest(TRANSPORT, JSON_FACTORY, tokenData.getRefreshToken(),
                    this.clientID, this.clientSecret);
            GoogleTokenResponse refreshed = refreshTokenRequest.execute();

            // Update only 'accessToken' with new value
            tokenData.setAccessToken(refreshed.getAccessToken());

            if (log.isLoggable(Level.FINEST)) {
                log.finest("AccessToken refreshed successfully with value " + refreshed.getAccessToken());
            }
        } catch (IOException ioe) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_GOOGLE_ERROR, ioe);
        }
    }

    // Parse given String and add all scopes from it to given Set
    private void addScopesFromString(String scope, Set<String> scopes) {
        String[] scopes2 = scope.split(" ");
        for (String current : scopes2) {
            scopes.add(current);
        }
    }
}
