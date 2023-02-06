package com.example.authserver.controller;

import com.example.authserver.repository.JpaCustomRegistgeredClientRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@AllArgsConstructor
public class MyController {

    private JpaCustomRegistgeredClientRepository jpaCustomRegistgeredClientRepository;

    @PostMapping("/client")
    public void saveClient() {
        jpaCustomRegistgeredClientRepository.save(RegisteredClient.withId("id").clientId("client").clientSecret("secret").clientName("name").clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC).authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE).scope(OidcScopes.OPENID).build());

    }
}
