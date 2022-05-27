package com.magadiflo.app.filter;

//*******************************
// Esta clase es un FILTRO
// Aunque en la sección de tutoriales de FILTROS se usaba la clase OncePerRequestFilter,
// pero en esta clase se hereda de BasicAuthenticationFilter que a su vez hereda de OncePerRequestFilter
//*******************************

import com.magadiflo.app.service.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    public static final String AUTHORIZATION = "Authorization";

    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    @Autowired
    private JwtService jwtService;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        LOGGER.info(">>> FILTER JWT...");
        //1° PROCESAMOS EL FILTRO
        String authHeader = request.getHeader(AUTHORIZATION);
        if(this.jwtService.isBearer(authHeader)){
            List<GrantedAuthority> authorities = this.jwtService.roles(authHeader).stream()
                    .map(role -> new SimpleGrantedAuthority(role)).collect(Collectors.toList());

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(this.jwtService.user(authHeader), null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // NOTA: Si en alguno de los casos anteriores, el token no está autorizado se producirá una excepción
        // esto porque desde el servicio se están lanzando las excepciones, y aquí lo continúa rebotando con no autorizado
        // es por ello que aquí no verificamos si es válido o no el token

        // 2° DEJAMOS PASAR A LA CADENA DE FILTROS
        chain.doFilter(request, response);
    }
}
