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

package org.gatein.security.oauth.web.facebook;

import org.gatein.security.oauth.common.InteractionState;
import org.gatein.security.oauth.common.OAuthConstants;
import org.gatein.security.oauth.common.OAuthPrincipal;
import org.gatein.security.oauth.common.OAuthProviderType;
import org.gatein.security.oauth.facebook.FacebookAccessTokenContext;
import org.gatein.security.oauth.facebook.GateInFacebookProcessor;
import org.gatein.security.oauth.social.FacebookPrincipal;
import org.gatein.security.oauth.utils.OAuthUtils;
import org.gatein.security.oauth.web.OAuthProviderFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Filter for integration with authentication handhsake via Facebook with usage of OAuth2
 *
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class FacebookFilter extends OAuthProviderFilter<FacebookAccessTokenContext> {

    @Override
    protected OAuthProviderType<FacebookAccessTokenContext> getOAuthProvider() {
        return getOAuthProviderTypeRegistry().getOAuthProvider(OAuthConstants.OAUTH_PROVIDER_KEY_FACEBOOK);
    }

    @Override
    protected void initInteraction(HttpServletRequest request, HttpServletResponse response) {
        request.getSession().removeAttribute(OAuthConstants.ATTRIBUTE_AUTH_STATE);
        request.getSession().removeAttribute(OAuthConstants.ATTRIBUTE_VERIFICATION_STATE);
    }

    @Override
    protected OAuthPrincipal<FacebookAccessTokenContext> getOAuthPrincipal(HttpServletRequest request, HttpServletResponse response,
                                                                           InteractionState<FacebookAccessTokenContext> interactionState) {
        FacebookAccessTokenContext accessTokenContext = interactionState.getAccessTokenContext();
        String accessToken = accessTokenContext.getAccessToken();
        FacebookPrincipal principal = ((GateInFacebookProcessor)getOauthProviderProcessor()).getPrincipal(accessToken);

        if (principal == null) {
            log.error("Principal was null");
            return null;
        } else {
            if (log.isTraceEnabled()) {
                log.trace("Finished Facebook OAuth2 flow with state: " + interactionState);
                log.trace("Facebook accessToken: " + principal.getAccessToken());
            }

            OAuthPrincipal<FacebookAccessTokenContext> oauthPrincipal = OAuthUtils.convertFacebookPrincipalToOAuthPrincipal(
                    principal, getOAuthProvider(), accessTokenContext.getAccessToken());

            return oauthPrincipal;
        }
    }
}
