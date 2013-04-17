package org.eventjuggler.services.idb.rest;

import java.net.URI;
import java.net.URISyntaxException;

import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriInfo;

import org.eventjuggler.services.idb.ApplicationService;
import org.eventjuggler.services.idb.model.Application;
import org.eventjuggler.services.simpleauth.rest.Authentication;
import org.eventjuggler.services.simpleauth.rest.AuthenticationRequest;
import org.eventjuggler.services.simpleauth.rest.AuthenticationResponse;
import org.jboss.resteasy.client.ProxyFactory;

@Path("/dummysocial/{appKey}")
public class DummySocialResource {

    @Inject
    private ApplicationService service;

    @GET
    @Produces(MediaType.TEXT_HTML)
    public Response getForm(@PathParam("appKey") String appKey, @Context UriInfo uri) {
        Application application = service.getApplication(appKey);
        if (application == null) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        StringBuilder sb = new StringBuilder();
        sb.append("<html>");
        sb.append("<body>");
        sb.append("<h1>Welcome to Dummy Social</h1>");
        sb.append(application.getName() + " is requesting to authenticate using your account");
        sb.append("<form action='#' method='post'>");
        sb.append("<input type='text' name='username' placeholder='Username' />");
        sb.append("<input type='text' name='password' placeholder='Password' />");
        sb.append("<input type='hidden' name='appkey' value='" + appKey + "' />");
        sb.append("<button type='submit'>Accept</button>");
        sb.append("</form>");
        sb.append("</body>");
        sb.append("</html>");

        return Response.ok(sb.toString()).build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response login(@PathParam("appKey") String appKey, @FormParam("username") String username,
            @FormParam("password") String password) throws URISyntaxException {
        Application application = service.getApplication(appKey);
        if (application == null) {
            return Response.status(Status.BAD_REQUEST).build();
        }

        Authentication auth = ProxyFactory.create(Authentication.class, "http://localhost:8080/ejs-identity/api");

        AuthenticationRequest request = new AuthenticationRequest();
        request.setUserId(username);
        request.setPassword(password);

        AuthenticationResponse response = auth.login(request);
        if (response.isLoggedIn()) {
            return Response.seeOther(
                    new URI("http://localhost:8080/ejs-identity/api/callback/" + appKey + "?token=" + response.getToken()))
                    .build();
        } else {
            return Response.status(Status.BAD_REQUEST).build();
        }
    }

}