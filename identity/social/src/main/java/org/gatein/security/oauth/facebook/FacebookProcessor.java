/*
 * JBoss, Home of Professional Open Source
 *
 * Copyright 2013 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.gatein.security.oauth.facebook;

import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.exception.OAuthException;
import org.gatein.security.oauth.exception.OAuthExceptionCode;
import org.gatein.security.oauth.utils.OAuthUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Processor to perform Facebook interaction
 *
 * @author Anil Saldhana
 * @since Sep 22, 2011
 */
public class FacebookProcessor {

    private static Logger log = Logger.getLogger(FacebookProcessor.class.getName());

    protected boolean trace = log.isLoggable(Level.FINEST);


    protected String clientID;
    protected String clientSecret;
    protected String scope;
    protected String returnURL;

    public FacebookProcessor(String clientID, String clientSecret, String scope, String returnURL) {
        super();
        this.clientID = clientID;
        this.clientSecret = clientSecret;
        this.scope = scope;
        this.returnURL = returnURL;
    }


    public boolean initialInteraction(HttpServletRequest request, HttpServletResponse response, String verificationState) throws IOException
    {
        Map<String, String> params = new HashMap<String, String>();
        params.put(OAuthConstants.REDIRECT_URI_PARAMETER, returnURL);
        params.put(OAuthConstants.CLIENT_ID_PARAMETER, clientID);
        params.put(OAuthConstants.STATE_PARAMETER, verificationState);

        if (scope != null) {
            params.put(OAuthConstants.SCOPE_PARAMETER, scope);
        }

        String location = new StringBuilder(FacebookConstants.SERVICE_URL).append("?").append(OAuthUtils.createQueryString(params))
                .toString();
        try {
            if (trace)
                log.finest("Redirect:" + location);
            response.sendRedirect(location);
            return false;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public String getAccessToken(HttpServletRequest request, HttpServletResponse response) throws OAuthException
    {
        String error = request.getParameter(OAuthConstants.ERROR_PARAMETER);
        if (error != null) {
            if (OAuthConstants.ERROR_ACCESS_DENIED.equals(error)) {
                throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_USER_DENIED_SCOPE, error);
            } else {
                throw new OAuthException(OAuthExceptionCode.EXCEPTION_UNSPECIFIED, error);
            }
        } else {
            String authorizationCode = request.getParameter(OAuthConstants.CODE_PARAMETER);
            if (authorizationCode == null) {
                log.severe("Authorization code parameter not found");
                return null;
            }

            String stateFromSession = (String)request.getSession().getAttribute(OAuthConstants.ATTRIBUTE_VERIFICATION_STATE);
            String stateFromRequest = request.getParameter(OAuthConstants.STATE_PARAMETER);
            if (stateFromSession == null || stateFromRequest == null || !stateFromSession.equals(stateFromRequest)) {
                throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_INVALID_STATE, "Validation of state parameter failed. stateFromSession="
                        + stateFromSession + ", stateFromRequest=" + stateFromRequest);
            }

            URLConnection connection = sendAccessTokenRequest(authorizationCode);

            Map<String, String> params;
            try {
                params = OAuthUtils.formUrlDecode(OAuthUtils.readUrlContent(connection));
            } catch (IOException ioe) {
                throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_FACEBOOK_ERROR, ioe);
            }

            String accessToken = params.get(OAuthConstants.ACCESS_TOKEN_PARAMETER);
            String expires = params.get(FacebookConstants.EXPIRES);

            if (trace)
                log.finest("Access Token=" + accessToken + " :: Expires=" + expires);

            return accessToken;
        }
    }

    protected URLConnection sendAccessTokenRequest(String authorizationCode) {
        String returnUri = returnURL;

        Map<String, String> params = new HashMap<String, String>();
        params.put(OAuthConstants.REDIRECT_URI_PARAMETER, returnUri);
        params.put(OAuthConstants.CLIENT_ID_PARAMETER, clientID);
        params.put(OAuthConstants.CLIENT_SECRET_PARAMETER, clientSecret);
        params.put(OAuthConstants.CODE_PARAMETER, authorizationCode);

        String location = new StringBuilder(FacebookConstants.ACCESS_TOKEN_ENDPOINT_URL).append("?")
                .append(OAuthUtils.createQueryString(params)).toString();

        try {
            if (trace)
                log.finest("AccessToken Request=" + location);
            URL url = new URL(location);
            URLConnection connection = url.openConnection();
            return connection;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public Set<String> getScopes(String accessToken) {
        try {
            String urlString = new StringBuilder(FacebookConstants.PROFILE_ENDPOINT_URL).append("/permissions").append("?access_token=")
                    .append(URLEncoder.encode(accessToken, "UTF-8")).toString();
            if (trace)
                log.finest("Read info about available scopes:" + urlString);

            URL scopeUrl = new URL(urlString);
            String scopeContent = OAuthUtils.readUrlContent(scopeUrl.openConnection());
            JSONObject jsonObject = new JSONObject(scopeContent);

            JSONArray json = jsonObject.getJSONArray("data");
            if (json != null) {
                jsonObject = json.optJSONObject(0);
                if (jsonObject != null) {
                    String[] names = JSONObject.getNames(jsonObject);
                    if (names != null) {
                        Set<String> scopes = new HashSet<String>();
                        for (String name : names) {
                            scopes.add(name);
                        }
                        return scopes;
                    }
                }
            }

            return new HashSet<String>();
        } catch (JSONException e) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_FACEBOOK_ERROR, e);
        } catch (IOException e) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_FACEBOOK_ERROR, e);
        }
    }

    public FacebookPrincipal getPrincipal(String accessToken) {
        FacebookPrincipal facebookPrincipal;
        try {
            String urlString = new StringBuilder(FacebookConstants.PROFILE_ENDPOINT_URL).append("?access_token=")
                    .append(URLEncoder.encode(accessToken, "UTF-8")).toString();
            if (trace)
                log.finest("Profile read:" + urlString);

            URL profileUrl = new URL(urlString);
            String profileContent = OAuthUtils.readUrlContent(profileUrl.openConnection());
            JSONObject jsonObject = new JSONObject(profileContent);

            facebookPrincipal = new FacebookPrincipal();
            facebookPrincipal.setAccessToken(accessToken);
            facebookPrincipal.setId(jsonObject.optString("id"));
            facebookPrincipal.setName(jsonObject.optString("name"));
            facebookPrincipal.setUsername(jsonObject.optString("username"));
            facebookPrincipal.setFirstName(jsonObject.optString("first_name"));
            facebookPrincipal.setLastName(jsonObject.optString("last_name"));
            facebookPrincipal.setGender(jsonObject.optString("gender"));
            facebookPrincipal.setTimezone(jsonObject.optString("timezone"));
            facebookPrincipal.setLocale(jsonObject.optString("locale"));
            facebookPrincipal.setEmail(jsonObject.optString("email"));
            facebookPrincipal.setJsonObject(jsonObject);
        } catch (JSONException e) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_FACEBOOK_ERROR, e);
        } catch (IOException e) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_FACEBOOK_ERROR, e);
        }

        return facebookPrincipal;
    }

    public void revokeToken(String accessToken) {
        try {
            String urlString = new StringBuilder(FacebookConstants.PROFILE_ENDPOINT_URL).append("/permissions?access_token=")
                    .append(URLEncoder.encode(accessToken, "UTF-8")).append("&method=delete").toString();
            URL revokeUrl = new URL(urlString);
            String revokeContent = OAuthUtils.readUrlContent(revokeUrl.openConnection());
            if (trace) {
                log.finest("Successfully revoked facebook accessToken " + accessToken + ", revokeContent=" + revokeContent);
            }
        } catch (IOException ioe) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_TOKEN_REVOKE_FAILED, "Error when revoking token", ioe);
        }
    }

}

