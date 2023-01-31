package com.example.authserver.repository;


import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;

import java.util.Optional;

//@Component
//@AllArgsConstructor
//public class JpaCustomRegistgeredClientRepository implements RegisteredClientRepository {
//
//    private ClientRepository clientRepository;
//
//    @Override
//    public void save(RegisteredClient registeredClient) {
//        System.out.println(registeredClient.toString()+"save");
//        Client client=new Client(registeredClient.getId(),registeredClient.getClientName(),registeredClient.getClientSecret(),registeredClient.getClientId());
//        clientRepository.save(client);
//    }
//
//    @Override
//    public RegisteredClient findById(String id) {
//        Optional<Client> client=clientRepository.findById(id);
//        Client real=client.get();
//        System.out.println(client.toString()+ "findById");
//
//        return    RegisteredClient.withId(real.getId()).clientId(real.getClientId()).clientSecret(real.getClientSecret()).build();
//    }
//
//    @Override
//    public RegisteredClient findByClientId(String clientId) {
//        Optional<Client> client=clientRepository.findClientByClientId(clientId);
//        Client real=client.get();
//        System.out.println(client.toString()+ "findByClientId");
//
//        return  RegisteredClient.withId(real.getId()).clientId(real.getClientId()).clientSecret(real.getClientSecret()).build();
//    }
//}
