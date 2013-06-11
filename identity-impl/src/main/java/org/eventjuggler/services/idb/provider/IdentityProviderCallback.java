/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2012, Red Hat, Inc., and individual contributors
 * as indicated by the @author tags. See the copyright.txt file in the
 * distribution for a full listing of individual contributors.
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
package org.eventjuggler.services.idb.provider;

import java.net.URI;
import java.util.List;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.UriInfo;

import org.eventjuggler.services.idb.model.Application;
import org.eventjuggler.services.idb.model.IdentityProviderConfig;
import org.eventjuggler.services.utils.UriBuilder;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class IdentityProviderCallback {

    private Application application;

    private HttpHeaders headers;

    private IdentityProvider provider;

    private IdentityProviderState providerState;

    public boolean containsState(String key) {
        return providerState.contains(key);
    }

    public <T> T getState(String key) {
        return providerState.remove(key);
    }

    public void putState(String key, Object value) {
        providerState.put(key, value);
    }

    public void setProviderState(IdentityProviderState providerState) {
        this.providerState = providerState;
    }

    private UriInfo uriInfo;

    public boolean containsHeader(String key) {
        return headers.getRequestHeaders().containsKey(key);
    }

    public boolean containsQueryParam(String key) {
        return uriInfo.getQueryParameters().containsKey(key);
    }

    public UriBuilder createUri(String path) {
        return new UriBuilder(headers, uriInfo, path);
    }

    public String getApplicationKey() {
        return application.getKey();
    }

    public URI getBrokerCallbackUrl() {
        return createUri("api/callback/" + application.getKey()).build();
    }

    private IdentityProviderConfig getConfig() {
        for (IdentityProviderConfig c : application.getProviders()) {
            if (c.getProviderId().equals(provider.getId())) {
                return c;
            }
        }
        return null;
    }

    public String getHeader(String key) {
        List<String> values = headers.getRequestHeaders().get(key);
        if (!values.isEmpty()) {
            return values.get(0);
        }
        return null;
    }

    public String getProviderKey() {
        return getConfig().getKey();
    }

    public String getProviderSecret() {
        return getConfig().getSecret();
    }

    public String getQueryParam(String key) {
        List<String> values = uriInfo.getQueryParameters().get(key);
        if (!values.isEmpty()) {
            return values.get(0);
        }
        return null;
    }

    public void setApplication(Application application) {
        this.application = application;
    }

    public void setHeaders(HttpHeaders headers) {
        this.headers = headers;
    }

    public void setProvider(IdentityProvider provider) {
        this.provider = provider;
    }

    public void setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
    }

}
