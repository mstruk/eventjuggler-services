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
package org.eventjuggler.services.idb.rest;

import java.io.Serializable;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.annotation.Resource;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.eventjuggler.services.idb.ApplicationService;
import org.eventjuggler.services.idb.model.Application;
import org.eventjuggler.services.idb.provider.IdentityProvider;
import org.eventjuggler.services.idb.provider.IdentityProviderCallback;
import org.eventjuggler.services.idb.provider.IdentityProviderService;
import org.eventjuggler.services.simpleauth.SimpleAuthIdmUtil;
import org.picketlink.idm.IdentityManager;
import org.picketlink.idm.IdentityManagerFactory;
import org.picketlink.idm.model.Attribute;
import org.picketlink.idm.model.IdentityType;
import org.picketlink.idm.model.User;

/**
 * @author <a href="mailto:sthorger@redhat.com">Stian Thorgersen</a>
 */
@Path("/callback/{appKey}")
@Stateless
public class CallbackResource {

    @EJB
    private ApplicationService applicationService;

    @Context
    private HttpHeaders headers;

    @Resource(lookup = "java:/picketlink/ExampleIMF")
    private IdentityManagerFactory imf;

    @Context
    private UriInfo uriInfo;

    @EJB
    private IdentityProviderService providerService;

    @GET
    public Response callback(@PathParam("appKey") String appKey) throws URISyntaxException {
        IdentityManager im = imf.createIdentityManager();

        Application application = applicationService.getApplication(appKey);
        if (application == null) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        IdentityProviderCallback callback = new IdentityProviderCallback();
        callback.setApplication(application);
        callback.setHeaders(headers);
        callback.setUriInfo(uriInfo);

        for (IdentityProvider provider : providerService.getProviders()) {
            callback.setProvider(provider);

            if (provider.isCallbackHandler(callback)) {
                User user = provider.getUser(callback);

                if (user == null) {

                }

                String providerUsername = user.getLoginName();
                String providerUsernameKey = provider.getId() + ".username";

                user.setAttribute(new Attribute<String>(providerUsernameKey, user.getLoginName()));

                List<User> l = im.createIdentityQuery(User.class)
                        .setParameter(IdentityType.ATTRIBUTE.byName(providerUsernameKey), providerUsername).getResultList();

                if (!l.isEmpty()) {
                    User existingUser = l.get(0);
                    updateUser(user, existingUser);
                    user = existingUser;

                    im.update(user);
                } else {
                    if (im.getUser(user.getLoginName()) != null) {
                        for (int i = 0;; i++) {
                            if (im.getUser(providerUsername + i) == null) {
                                user.setLoginName(providerUsername + i);
                                break;
                            }
                        }
                    }

                    im.add(user);
                }

                String token = new SimpleAuthIdmUtil(im).setToken(user);

                URI uri = callback.createUri(application.getCallbackUrl() + "?token=" + token).build();
                return Response.seeOther(uri).build();
            }
        }

        return Response.status(Status.BAD_REQUEST).build();
    }

    private void updateUser(User source, User destination) {
        if (source.getEmail() != null) {
            destination.setEmail(source.getEmail());
        }

        if (source.getFirstName() != null) {
            destination.setFirstName(source.getFirstName());
        }

        if (source.getLastName() != null) {
            destination.setLastName(source.getLastName());
        }

        for (Attribute<? extends Serializable> attribute : source.getAttributes()) {
            destination.setAttribute(attribute);
        }
    }

}
