package com.example.authserver.repository;


import com.example.authserver.Client;
import com.example.authserver.repository.jpa.ClientRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Optional;

@Component
@AllArgsConstructor
public class JpaCustomRegistgeredClientRepository implements RegisteredClientRepository {

    private ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        System.out.println(registeredClient.toString() + "save");
        Client client = new Client(registeredClient.getId(), registeredClient.getClientName(), registeredClient.getClientSecret(), registeredClient.getClientId());
        clientRepository.save(client);
    }

    @Override
    public RegisteredClient findById(String id) {
        Optional<Client> client = clientRepository.findById(id);
        Client real = client.get();
        System.out.println(client.toString() + "findById");


        return RegisteredClient.withId("1f176f6a-5fd3-48fc-b0a6-7d8b08ad1d0d")
                //username
                .clientId("client")
                //password
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:3000/authorized")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        //now need PKCE
                        //ako ne kazemo requireProof mozemo i sa pkc da radimo a mozemo i bez,fora je sto kada imamo pkc
                        // ne moramo client secrete da saljemo sto je vise secure
//
//                  .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofHours(10))
                        .build())
                .build();
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Optional<Client> client = clientRepository.findClientByClientId(clientId);
        Client real = client.get();
        System.out.println(client.toString() + "findByClientId");

        return RegisteredClient.withId("1f176f6a-5fd3-48fc-b0a6-7d8b08ad1d0d")
                //username
                .clientId("client")
                //password
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:3000/authorized")
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        //now need PKCE
                        //ako ne kazemo requireProof mozemo i sa pkc da radimo a mozemo i bez,fora je sto kada imamo pkc
                        // ne moramo client secrete da saljemo sto je vise secure
//
//                  .requireProofKey(true)
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .refreshTokenTimeToLive(Duration.ofHours(10))
                        .build())
                .build();
    }
}
