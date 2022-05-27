package com.magadiflo.app.controller;

import com.magadiflo.app.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping(JwtController.JWTS)
public class JwtController {

    public static final String JWTS = "/jwts";
    public static final String TOKEN = "/token";

    @Autowired
    private JwtService jwtService;

    /**
     * La autenticación lo haremos mediante el Auth Basic (usuario y contraseña)
     * Le pedimos a Spring que nos pase @AuthenticationPrincipal, es decir que
     * nos pase el usuario que se ha logueado. ¿Dónde se ha logueado? se disparará
     * el Servicio de Usuarios y ahí es donde se va a loguear
     */
    @PreAuthorize("authenticated")
    @PostMapping(value = TOKEN)
    public String login(@AuthenticationPrincipal User activeUser) {
        System.out.println("login()");
        List<String> roleList = activeUser.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList());
        return this.jwtService.createToken(activeUser.getUsername(), roleList);
    }

    @PreAuthorize("hasRole('USER')")
    @GetMapping
    public String verify(){
        return "OK. permitido JWT";
    }
}
