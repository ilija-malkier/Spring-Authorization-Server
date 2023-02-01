package com.example.authserver.repository.jpa;

import com.example.authserver.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> {

    Optional<Client> findClientByClientId(String clientID);
}
