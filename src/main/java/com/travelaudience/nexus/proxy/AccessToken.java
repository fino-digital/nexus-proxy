package com.travelaudience.nexus.proxy;

import com.google.api.client.json.jackson2.JacksonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;
import java.io.IOException;

public class AccessToken {
    private final String rawToken;

    public AccessToken(String token) {
        rawToken = token;
    }

    public String principal(String claim) throws IOException {
        JsonWebSignature jws = JsonWebSignature
                .parser(JacksonFactory.getDefaultInstance())
                .parse(rawToken);
        return (String)jws.getPayload().get(claim);
    }
}
