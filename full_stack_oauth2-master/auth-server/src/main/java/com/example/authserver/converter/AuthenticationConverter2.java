package com.example.authserver.converter;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class AuthenticationConverter2 implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {

        return null;
    }
}
