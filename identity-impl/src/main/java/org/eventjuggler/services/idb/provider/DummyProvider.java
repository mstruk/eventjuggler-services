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

import javax.naming.InitialContext;

import org.eventjuggler.services.idb.rest.DummySocialResource;
import org.picketlink.idm.model.User;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
public class DummyProvider implements IdentityProvider {

    @Override
    public String getIcon() {
        return "dummy.png";
    }

    @Override
    public String getId() {
        return "dummy";
    }

    @Override
    public URI getLoginUrl(IdentityProviderCallback callback) {
        return callback.createUri("api/dummysocial/" + callback.getApplicationKey()).build();
    }

    @Override
    public String getName() {
        return "My Dummy Social Site";
    }

    @Override
    public User processCallback(IdentityProviderCallback callback) {
        String dummytoken = callback.getQueryParam("dummytoken");

        try {
            DummySocialResource dummySocialResource = (DummySocialResource) new InitialContext()
                    .lookup("java:global/ejs/DummySocialResource");
            return dummySocialResource.getUser(dummytoken);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    public boolean isCallbackHandler(IdentityProviderCallback callback) {
        return callback.containsQueryParam("dummytoken");
    }

}
