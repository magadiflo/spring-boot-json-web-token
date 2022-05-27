package com.magadiflo.app.service;

//***********************************************************
// ****** Esta clase será la FACHADA, que permitirá hacer más
// simple el uso de la librería de JWT
//***********************************************************

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.magadiflo.app.exeptions.JwtException;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    public static final String BEARER = "Bearer ";

    private static final String USER = "user";
    private static final String ROLES = "roles";
    private static final String ISSUER = "miw-spring5-magadiflo";
    private static final int EXPIRES_IN_MILLISECOND = 3600000;
    private static final String SECRET = "clave-secreta-test";

    public String createToken(String user, List<String> roles) {
        return JWT.create()
                .withIssuer(ISSUER) //Nombre de empresa
                .withIssuedAt(new Date()) //Fecha de creación
                .withNotBefore(new Date()) //Fecha a partir de qué momento será válido el token
                .withExpiresAt(new Date(System.currentTimeMillis() + EXPIRES_IN_MILLISECOND)) //Fecha de expiración del token
                .withArrayClaim(ROLES, roles.toArray(new String[0]))
                .sign(Algorithm.HMAC256(SECRET));
    }

    //En el tutorial le ponen 'authorization' como nombre de variable
    //Yo le puse 'token', para que sea más entendible
    public Boolean isBearer(String token) {
        return token != null && token.startsWith(BEARER) && token.split("\\.").length == 3;
    }

    public String user(String token) throws JwtException {
        return this.verify(token).getClaim(USER).asString();
    }

    public List<String> roles(String token) throws JwtException {
        return Arrays.asList(this.verify(token).getClaim(ROLES).asArray(String.class));
    }

    private DecodedJWT verify(String token) throws JwtException {
        if (!this.isBearer(token)) {
            throw new JwtException("It is not Bearer");
        }
        try {
            return JWT.require(Algorithm.HMAC256(SECRET))
                    .withIssuer(ISSUER).build()
                    .verify(token.substring(BEARER.length()));
        } catch (Exception e) {
            throw new JwtException("JWT is wrong. ".concat(e.getMessage()));
        }
    }

}
