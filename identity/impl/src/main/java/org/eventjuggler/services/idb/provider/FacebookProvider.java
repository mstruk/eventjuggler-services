package org.eventjuggler.services.idb.provider;

import org.codehaus.jackson.map.ObjectMapper;
import org.eventjuggler.services.utils.IOUtils;
import org.picketlink.idm.model.SimpleUser;
import org.picketlink.idm.model.User;

import javax.inject.Inject;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLConnection;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author <a href="mailto:marko.strukelj@gmail.com">Marko Strukelj</a>
 */
public class FacebookProvider implements IdentityProvider {


    private static final Logger log = Logger.getLogger(FacebookProvider.class.getName());

    private static final String UTF_8 = "utf-8";

    @Inject
    private Session session;

    @Override
    public String getId() {
        return "facebook";
    }

    @Override
    public URI getLoginUrl(IdentityProviderCallback callback) {
        return callback.createUri("https://www.facebook.com/dialog/oauth")
            .setQueryParam("client_id", callback.getProviderKey())
            .setQueryParam("scope", "email") // that's default value
            .setQueryParam("redirect_uri", callback.getBrokerCallbackUrl().toString())
            .setQueryParam("state", session.getState())
            .build();
    }

    @Override
    public String getIcon() {
        return "facebook.png";
    }

    @Override
    public String getName() {
        return "Facebook";
    }

    @Override
    public User getUser(IdentityProviderCallback callback) {

        // Managing first request
        String code = session.getCode();
        if (code == null) {
            code = callback.getQueryParam("code");
            if (code != null) {
                System.out.println("Received code from Facebook: " + code);
                session.setCode(code);
            }
        }

        // Access token
        String accessToken = session.getAccessToken();

        if (accessToken == null && code == null) {
            return null;
        } else if (accessToken == null) {
            URI uri = callback.createUri("https://graph.facebook.com/oauth/access_token")
                .setQueryParam("client_id", callback.getProviderKey())
                .setQueryParam("client_secret", callback.getProviderSecret())
                .setQueryParam("redirect_uri", callback.getBrokerCallbackUrl().toString())
                .setQueryParam("code", code)
                .build();

            System.out.println("Contacting facebook with separate HTTP request for obtain accessToken " + uri);

            accessToken = loadAccessTokenAndExpires(uri);
            System.out.println("Saving access token from Facebook to session. Token is " + accessToken);
            session.setAccessToken(accessToken);
        }

        if (accessToken != null) {
            URI uri = callback.createUri("https://graph.facebook.com/me")
                .setQueryParam("access_token", accessToken)
                .build();

            String response = sendRequestAndGetResponse(uri);
            // parse JSON
            /*

            {
  "id": "XXXXXXXXX",
  "name": "XXX YYYY",
  "first_name": "XXX",
  "last_name": "YYYY",
  "link": "https://www.facebook.com/UUUU",
  "username": "UUUU",
  "gender": "male",
  "email": "A@B.C",
  "timezone": 2,
  "locale": "en_US",
  "verified": true,
  "updated_time": "2013-02-28T20:52:05+0000"
}
             */


            try {
                ObjectMapper mapper = new ObjectMapper();
                Map<String, String> userProfile = mapper.readValue(response, Map.class);
                User user = new SimpleUser(userProfile.get("email"));
                user.setFirstName(userProfile.get("first_name"));
                user.setLastName(userProfile.get("last_name"));
                user.setEmail(userProfile.get("email"));
                user.setId(userProfile.get("id"));

                return user;
            } catch (IOException e) {
                log.log(Level.SEVERE, "Failed to parse Facebook Graph response: " + response, e);
            }
        }

        return null;
    }

    private String loadAccessTokenAndExpires(URI url) {
        String token = sendRequestAndGetResponse(url);
        log.finest("Obtaining line with token: " + token);
        Map<String, String> params = IOUtils.formUrlDecode(token);
        return params.get("access_token");
    }

    private String sendRequestAndGetResponse(URI url) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try {
            URLConnection con = url.toURL().openConnection();
            InputStream in = con.getInputStream();
            IOUtils.copyWithDefaultLimit(in, baos);
        } catch (IOException e) {
            log.log(Level.SEVERE, "Failed to get response from Facebook: " + url, e);
            return null;
        }

        try {
            return new String(baos.toByteArray(), UTF_8);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException("Java Runtime does not support utf-8");
        }
    }

    @Override
    public boolean isCallbackHandler(IdentityProviderCallback callback) {
        return callback.containsQueryParam("state") && callback.getQueryParam("state").equals(session.getState());
    }
}
