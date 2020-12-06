package com.chintamanidesai.security.jwt.app.config;

import org.springframework.security.core.userdetails.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Date;

public class AuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private static final String AUTHORIZATION = "Authorization";
    private static final String BEARER = "Bearer";

    private final AuthenticationManager authenticationManager;
    private final String signingKey;
    private final long jwtExpirationTimeInMS;

    public AuthenticationFilter(AuthenticationManager authenticationManager, String signingKey, long jwtExpirationTimeInMS) {
        this.authenticationManager = authenticationManager;
        this.signingKey = signingKey;
        this.jwtExpirationTimeInMS = jwtExpirationTimeInMS;
        setFilterProcessesUrl("/v1/users/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        try {
            com.chintamanidesai.security.jwt.app.model.User creds = new ObjectMapper().readValue(request.getInputStream(), com.chintamanidesai.security.jwt.app.model.User.class);
            return authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(creds.getUsername(), creds.getPassword(), new ArrayList<>()));
        } catch (IOException e) {
           throw new RuntimeException("Could not read request: " + e);
        }
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) {

        String token = Jwts.builder()
                .setSubject(((User) authentication.getPrincipal()).getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationTimeInMS))
                .signWith(SignatureAlgorithm.HS512, signingKey.getBytes())
                .compact();

       response.setHeader(AUTHORIZATION,BEARER + " " + token);
    }
}
