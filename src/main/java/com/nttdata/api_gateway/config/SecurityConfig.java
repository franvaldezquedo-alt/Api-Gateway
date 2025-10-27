package com.nttdata.api_gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {
  @Bean
  public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
    http
          .csrf(ServerHttpSecurity.CsrfSpec::disable)
          .authorizeExchange(exchange -> exchange
                // Rutas públicas (no requieren autenticación)
                .pathMatchers("/actuator/**").permitAll()
                .pathMatchers("/public/**").permitAll()

                // Todas las demás rutas requieren autenticación
                .anyExchange().authenticated()
          )
          .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> {})
          );

    return http.build();
  }
}
