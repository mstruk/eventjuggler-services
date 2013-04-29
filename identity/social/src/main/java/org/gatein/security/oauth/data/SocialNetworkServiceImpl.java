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

package org.gatein.security.oauth.data;

import org.eventjuggler.services.simpleim.rest.User;
import org.gatein.security.oauth.common.AccessTokenContext;
import org.gatein.security.oauth.common.OAuthCodec;
import org.gatein.security.oauth.common.OAuthProviderProcessor;
import org.gatein.security.oauth.common.OAuthProviderType;
import org.gatein.security.oauth.exception.OAuthException;
import org.gatein.security.oauth.im.OrganizationService;
import org.gatein.security.oauth.im.UserHandler;
import org.gatein.security.oauth.im.UserProfile;
import org.gatein.security.oauth.im.UserProfileHandler;

import java.lang.reflect.Method;
import java.util.logging.Logger;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class SocialNetworkServiceImpl implements SocialNetworkService, OAuthCodec {

    private static Logger log = Logger.getLogger(SocialNetworkServiceImpl.class.getName());

    private OrganizationService orgService;

    public SocialNetworkServiceImpl(OrganizationService orgService) {
        this.orgService = orgService;
    }

    @Override
    public User findUserByOAuthProviderUsername(OAuthProviderType oauthProviderType, String oauthProviderUsername) {
        UserHandler userHandler = orgService.getUserHandler();

        // TODO: Ugly, but it's used due to OrganizationService API limitations because it doesn't allow to find user by unique userProfile attribute
        try {
            Method m = userHandler.getClass().getDeclaredMethod("findUserByUniqueAttribute", String.class, String.class);
            return (User)m.invoke(userHandler, oauthProviderType.getUserNameAttrName(), oauthProviderUsername);
        } catch (NoSuchMethodException e) {
            String error = "Method findUserByUniqueAttribute(String, String) is not available on userHandler object " + userHandler +
                    "of class " + userHandler.getClass();
            log.severe(error);
            throw new RuntimeException(error, e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T extends AccessTokenContext> void updateOAuthAccessToken(OAuthProviderType<T> oauthProviderType, String username, T accessToken) {
        try {
            UserProfileHandler userProfileHandler = orgService.getUserProfileHandler();
            UserProfile userProfile = userProfileHandler.findUserProfileByName(username);

            OAuthProviderProcessor<T> oauthProviderProcessor = oauthProviderType.getOauthProviderProcessor();
            oauthProviderProcessor.saveAccessTokenAttributesToUserProfile(userProfile, this, accessToken);

            userProfileHandler.saveUserProfile(userProfile, true);
        } catch (OAuthException gtnEx) {
            throw gtnEx;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T extends AccessTokenContext> T getOAuthAccessToken(OAuthProviderType<T> oauthProviderType, String username) {
        try {
            UserProfileHandler userProfileHandler = orgService.getUserProfileHandler();
            UserProfile userProfile = userProfileHandler.findUserProfileByName(username);

            OAuthProviderProcessor<T> oauthProviderProcessor = oauthProviderType.getOauthProviderProcessor();
            return oauthProviderProcessor.getAccessTokenFromUserProfile(userProfile, this);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T extends AccessTokenContext> void removeOAuthAccessToken(OAuthProviderType<T> oauthProviderType, String username) {
        try {
            UserProfileHandler userProfileHandler = orgService.getUserProfileHandler();
            UserProfile userProfile = userProfileHandler.findUserProfileByName(username);

            OAuthProviderProcessor<T> oauthProviderProcessor = oauthProviderType.getOauthProviderProcessor();
            oauthProviderProcessor.removeAccessTokenFromUserProfile(userProfile);

            userProfileHandler.saveUserProfile(userProfile, true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public <T extends AccessTokenContext> void updateOAuthInfo(OAuthProviderType<T> oauthProviderType, String username, String oauthUsername, T accessToken) {
        try {
            UserProfileHandler userProfileHandler = orgService.getUserProfileHandler();
            UserProfile userProfile = userProfileHandler.findUserProfileByName(username);

            userProfile.setAttribute(oauthProviderType.getUserNameAttrName(), oauthUsername);

            OAuthProviderProcessor<T> oauthProviderProcessor = oauthProviderType.getOauthProviderProcessor();
            oauthProviderProcessor.saveAccessTokenAttributesToUserProfile(userProfile, this, accessToken);
            userProfileHandler.saveUserProfile(userProfile, true);
        } catch (OAuthException gtnEx) {
            throw gtnEx;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public String encodeString(String input) {
        return input;
    }

    @Override
    public String decodeString(String input) {
        return input;
    }

}