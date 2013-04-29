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

package org.gatein.security.oauth.twitter;


import org.gatein.security.oauth.common.InteractionState;
import org.gatein.security.oauth.common.OAuthCodec;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.exception.OAuthException;
import org.gatein.security.oauth.exception.OAuthExceptionCode;
import org.gatein.security.oauth.im.UserProfile;
import org.gatein.security.oauth.common.SocialServiceConfiguration;
import twitter4j.Twitter;
import twitter4j.TwitterException;
import twitter4j.TwitterFactory;
import twitter4j.auth.AccessToken;
import twitter4j.auth.RequestToken;
import twitter4j.conf.ConfigurationBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class TwitterProcessorImpl implements TwitterProcessor {

    private static Logger log = Logger.getLogger(TwitterProcessorImpl.class.getName());

    private final String redirectUrl;
    private final String clientID;
    private final String clientSecret;
    private final TwitterFactory twitterFactory;

    public TwitterProcessorImpl(SocialServiceConfiguration conf) {
        this.clientID = conf.getClientId();
        this.clientSecret = conf.getClientSecret();
        this.redirectUrl = conf.getRedirectUrl();

        if (clientID == null || clientID.length() == 0 || clientID.trim().equals("<<to be replaced>>")) {
            throw new IllegalArgumentException("Property 'clientId' needs to be provided. The value should be " +
                    "clientId of your Twitter application");
        }

        if (clientSecret == null || clientSecret.length() == 0 || clientSecret.trim().equals("<<to be replaced>>")) {
            throw new IllegalArgumentException("Property 'clientSecret' needs to be provided. The value should be " +
                    "clientSecret of your Twitter application");
        }

        if (redirectUrl == null || redirectUrl.length() == 0 || redirectUrl.trim().equals("<<to be replaced>>")) {
            throw new IllegalArgumentException("Property 'redirectUrl' needs to be provided.");
        }


        log.fine("configuration: clientId=" + clientID +
            ", clientSecret=" + clientSecret +
            ", redirectUrl=" + redirectUrl);

        // Create 'generic' twitterFactory for user authentication to GateIn
        ConfigurationBuilder builder = new ConfigurationBuilder();
        builder.setOAuthConsumerKey(clientID).setOAuthConsumerSecret(clientSecret);
        twitterFactory = new TwitterFactory(builder.build());
    }

    @Override
    public InteractionState<TwitterAccessTokenContext> processOAuthInteraction(HttpServletRequest request, HttpServletResponse response) throws
       IOException, OAuthException {
        Twitter twitter = twitterFactory.getInstance();

        HttpSession session = request.getSession();

        //See if we are a callback
        RequestToken requestToken = (RequestToken) session.getAttribute(OAuthConstants.ATTRIBUTE_TWITTER_REQUEST_TOKEN);

        try {
            if (requestToken == null) {
                requestToken = twitter.getOAuthRequestToken(redirectUrl);

                // Save requestToken to session, but only temporarily until oauth workflow is finished
                session.setAttribute(OAuthConstants.ATTRIBUTE_TWITTER_REQUEST_TOKEN, requestToken);

                if (log.isLoggable(Level.FINEST)) {
                    log.finest("RequestToken obtained from twitter. Redirecting to Twitter for authorization");
                }

                // Redirect to twitter to perform authentication
                response.sendRedirect(requestToken.getAuthenticationURL());

                return new InteractionState<TwitterAccessTokenContext>(InteractionState.State.AUTH, null);
            } else {
                String verifier = request.getParameter(OAuthConstants.OAUTH_VERIFIER);

                // Obtain accessToken from twitter
                AccessToken accessToken = twitter.getOAuthAccessToken(requestToken, verifier);

                if (log.isLoggable(Level.FINEST)) {
                    log.finest("Twitter accessToken: " + accessToken);
                }

                // Remove requestToken from session. We don't need it anymore
                session.removeAttribute(OAuthConstants.ATTRIBUTE_TWITTER_REQUEST_TOKEN);
                TwitterAccessTokenContext accessTokenContext = new TwitterAccessTokenContext(accessToken.getToken(), accessToken.getTokenSecret());

                return new InteractionState<TwitterAccessTokenContext>(InteractionState.State.FINISH, accessTokenContext);
            }
        } catch (TwitterException twitterException) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_TWITTER_ERROR, twitterException);
        }
    }

    @Override
    public InteractionState<TwitterAccessTokenContext> processOAuthInteraction(HttpServletRequest httpRequest, HttpServletResponse httpResponse, String scope) throws IOException, OAuthException {
        throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_TWITTER_ERROR, "This is currently not supported for Twitter");
    }

    @Override
    public Twitter getAuthorizedTwitterInstance(TwitterAccessTokenContext accessTokenContext) {
        ConfigurationBuilder builder = new ConfigurationBuilder();
        builder.setOAuthConsumerKey(clientID).setOAuthConsumerSecret(clientSecret);

        // Now add accessToken properties to builder
        builder.setOAuthAccessToken(accessTokenContext.getAccessToken());
        builder.setOAuthAccessTokenSecret(accessTokenContext.getAccessTokenSecret());

        // Return twitter instance with successfully established accessToken
        return new TwitterFactory(builder.build()).getInstance();
    }

    @Override
    public void saveAccessTokenAttributesToUserProfile(UserProfile userProfile, OAuthCodec codec, TwitterAccessTokenContext accessToken) {
        String encodedAccessToken = codec.encodeString(accessToken.getAccessToken());
        String encodedAccessTokenSecret = codec.encodeString(accessToken.getAccessTokenSecret());
        userProfile.setAttribute(OAuthConstants.PROFILE_TWITTER_ACCESS_TOKEN, encodedAccessToken);
        userProfile.setAttribute(OAuthConstants.PROFILE_TWITTER_ACCESS_TOKEN_SECRET, encodedAccessTokenSecret);
    }

    @Override
    public TwitterAccessTokenContext getAccessTokenFromUserProfile(UserProfile userProfile, OAuthCodec codec) {
        String decodedAccessToken = codec.decodeString(userProfile.getAttribute(OAuthConstants.PROFILE_TWITTER_ACCESS_TOKEN));
        String decodedAccessTokenSecret = codec.decodeString(userProfile.getAttribute(OAuthConstants.PROFILE_TWITTER_ACCESS_TOKEN_SECRET));

        if (decodedAccessToken == null || decodedAccessTokenSecret == null) {
            return null;
        } else {
            return new TwitterAccessTokenContext(decodedAccessToken, decodedAccessTokenSecret);
        }
    }


    @Override
    public TwitterAccessTokenContext validateTokenAndUpdateScopes(TwitterAccessTokenContext accessToken) throws OAuthException {
        try {
            // Perform validation by obtaining some info about user
            Twitter twitter = getAuthorizedTwitterInstance(accessToken);
            twitter.verifyCredentials();
            return accessToken;
        } catch (TwitterException tw) {
            throw new OAuthException(OAuthExceptionCode.EXCEPTION_CODE_TWITTER_ERROR, tw);
        }
    }

    @Override
    public void removeAccessTokenFromUserProfile(UserProfile userProfile) {
        userProfile.setAttribute(OAuthConstants.PROFILE_TWITTER_ACCESS_TOKEN, null);
        userProfile.setAttribute(OAuthConstants.PROFILE_TWITTER_ACCESS_TOKEN_SECRET, null);
    }

    @Override
    public void revokeToken(TwitterAccessTokenContext accessToken) {
        // TODO: (if it's possible with Twitter... Maybe it's noop)
    }
}