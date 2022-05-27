package com.magadiflo.app.security;

import com.magadiflo.app.filter.JwtAuthorizationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //Aquí usaríamos el userDetailService, pero como solo usaremos usuarios en memoria
    // y no de Base de Datos, en este caso no es necesario
    //@Autowired
    //UserDetailsService userDetailsService;

    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //Configuramos el manejo de usuarios
    @Override
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //Como se comentó arriba, aquí se haría el llamado al DAO para obtener los
        // usuarios de la BD usando el userDetailsService, pero como solo usaremos
        // usuarios en memoria no es necesario

        //**** De Memoria
        auth.inMemoryAuthentication() //static users
                .withUser("user").password(passwordEncoder().encode("12345")).roles("USER") //Es necesario codificarlo para hacer match en el UserDetailsServiceImpl
                .and()
                .withUser("manager").password(passwordEncoder().encode("12345")).roles("MANAGER")
                .and()
                .withUser("admin").password(passwordEncoder().encode("12345")).roles("ADMIN", "MANAGER", "USER");
    }

    //Configuración de la seguridad Global del sistema
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .httpBasic()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().addFilter(this.jwtAuthorizationFilter());
    }

    //Configurando el Filtro según el tutorial de Security
    @Bean
    public JwtAuthorizationFilter jwtAuthorizationFilter() throws Exception {
        return new JwtAuthorizationFilter(this.authenticationManager());
    }
}
