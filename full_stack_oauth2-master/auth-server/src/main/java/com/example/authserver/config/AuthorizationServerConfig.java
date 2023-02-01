package com.example.authserver.config;

import com.example.authserver.config.keys.JwksKeys;
import com.example.authserver.repository.JpaCustomRegistgeredClientRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.time.Duration;
import java.util.UUID;

@Configuration
@AllArgsConstructor
public class AuthorizationServerConfig {

  // http://localhost:8080/oauth2/authorize?response_type=code&client_id=client&scope=openid&redirect_uri=http://127.0.0.1:3000/authorized&code_challenge=QYPAZ5NU8yvtlQ9erXrUYR-T5AGCjCF47vN-KsaI2A8&code_challenge_method=S256
  // http://localhost:8080/oauth2/token?client_id=client&redirect_uri=http://127.0.0.1:3000/authorized&grant_type=authorization_code&code=MJ5WmUiOAnVFHi9BS6PS5dqHvO56fHkQVqR8gUg-yOmpgohvsFmH4xU6lFcwwDN0nkAcYdldOROnhAhf0cDROu-PgSup94fx28geM4p08TSEZ_c9c9vkL_yy34WBfnyY&code_verifier=qPsH306-ZDDaOE8DFzVn05TkN3ZZoVmI_6x4LsVglQI

    private final CORSCustomizer corsCustomizer;
    private JpaCustomRegistgeredClientRepository jpaCustomRegistgeredClientRepository;

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain securityASFilterChain(HttpSecurity http) throws Exception {
      OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
//    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
//            new OAuth2AuthorizationServerConfigurer();
//      http.apply(authorizationServerConfigurer);
//
//      authorizationServerConfigurer.authorizationEndpoint(authorizationServerEndpointConfigurer->{
//        authorizationServerEndpointConfigurer
//                .authorizationRequestConverter(new BasicAuthenticationConverter())
//                .consentPage("http://127.0.0.1:3000/consent")
////                .authorizationResponseHandler("custom")
//        ;
//    });
//


// Enable OpenID Connect 1.0
      http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());
      //if user is not auth redirect it to login page
      http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
              // Accept access tokens for User Info and/or Client Registration
              .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
      corsCustomizer.corsCustomizer(http);

      return http.formLogin().and().build();
  }

    //cela poenta Authorization servera je ako neko 3th party zatrazi neke personal info iz nase app da mu mi kao priredimo postupak kao sto ima google
    // sa login with google,ovo registedClientRepository je u stvari skup user-a koji su registrovani na app i oni mogu da daju consent .Dosta je slicno
    //kao user details service ali samo sto ne radi sa user-om nego sa client-om imarazlike ovde

//  @Bean
//  public RegisteredClientRepository registeredClientRepository() {
//    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//            //username
//            .clientId("client")
//            //password
//            .clientSecret("secret")
//        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//        .redirectUri("http://127.0.0.1:3000/authorized")
//        .scope(OidcScopes.OPENID)
//        .clientSettings(ClientSettings.builder()
//            .requireAuthorizationConsent(true)
//                //now need PKCE
//                //ako ne kazemo requireProof mozemo i sa pkc da radimo a mozemo i bez,fora je sto kada imamo pkc
//                // ne moramo client secrete da saljemo sto je vise secure
////
////                  .requireProofKey(true)
//                .build())
//        .tokenSettings(TokenSettings.builder()
//            .refreshTokenTimeToLive(Duration.ofHours(10))
//            .build())
//        .build();
//
//
//    return new InMemoryRegisteredClientRepository(registeredClient);
//  }

    //default jdbc
//  @Bean
//  public RegisteredClientRepository registeredClientRepositoryJDBC(JdbcTemplate jdbcTemplate) {
//    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
//            //username
//            .clientId("client")
//            //password
//            .clientSecret("secret")
//        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//        .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//        .redirectUri("http://127.0.0.1:3000/authorized")
//        .scope(OidcScopes.OPENID)
//        .clientSettings(ClientSettings.builder()
//            .requireAuthorizationConsent(true)
//                //now need PKCE
//                //ako ne kazemo requireProof mozemo i sa pkc da radimo a mozemo i bez,fora je sto kada imamo pkc
//                // ne moramo client secrete da saljemo sto je vise secure
////
////                  .requireProofKey(true)
//                .build())
//        .tokenSettings(TokenSettings.builder()
//            .refreshTokenTimeToLive(Duration.ofHours(10))
//            .build())
//        .build();
//    JdbcRegisteredClientRepository jdbcRegisteredClientRepository=new JdbcRegisteredClientRepository(jdbcTemplate);
//    jdbcRegisteredClientRepository.save(registeredClient);
//
//
//    return jdbcRegisteredClientRepository;
//  }
    @Bean
    @Primary
    public RegisteredClientRepository registeredClientRepositoryJDBC(JdbcTemplate jdbcTemplate) {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
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


        return jpaCustomRegistgeredClientRepository;
    }


  //define endpoints for oid and oauth2 endpoints,default now
  //provider settings
  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().issuer("http://localhost:8080").build();
  }

  //key pair for signing tokens
  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    //key set je jer je ovo set pa moze da ima vise keypaira pa moze da ih rotira

    RSAKey rsaKey = JwksKeys.generateRSAKey();
    JWKSet set = new JWKSet(rsaKey);
    return new ImmutableJWKSet<>(set);
  }

  @Bean
  public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
    return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
  }
}
