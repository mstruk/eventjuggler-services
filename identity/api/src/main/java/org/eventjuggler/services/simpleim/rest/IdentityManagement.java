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
package org.eventjuggler.services.simpleim.rest;

import java.util.List;

import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.eventjuggler.services.simpleauth.rest.UserInfo;

@Path("/im")
public interface IdentityManagement {

    @GET
    @Path("/users/{username}")
    @Produces(MediaType.APPLICATION_JSON)
    UserInfo getUser(@PathParam("username") String username);

    @GET
    @Path("/users")
    @Produces(MediaType.APPLICATION_JSON)
    List<UserInfo> getUsers();

    @PUT
    @Path("/users/{username}")
    @Consumes(MediaType.APPLICATION_JSON)
    void saveUser(@PathParam("username") String username, User user);

    @DELETE
    @Path("/users/{username}")
    void deleteUser(@PathParam("username") String username);

}