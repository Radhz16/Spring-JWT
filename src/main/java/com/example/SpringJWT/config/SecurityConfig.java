package com.example.SpringJWT.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final JWTAuthenticationFilter jwtAuthFilter; // JWT filter to process the token
    private final AuthenticationProvider authenticationProvider;

    public SecurityConfig(JWTAuthenticationFilter jwtAuthFilter, AuthenticationProvider authenticationProvider) {
        this.jwtAuthFilter = jwtAuthFilter;
        this.authenticationProvider = authenticationProvider;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Configure HTTP security to disable CSRF and configure authentication
        http.csrf().disable()
                .authorizeRequests()
                .requestMatchers(HttpMethod.POST, "/api/v1/auth/register", "/api/v1/auth/authenticate") // Using requestMatchers instead of antMatchers
                .permitAll()  // Allow the register and authenticate endpoints without authentication
                .anyRequest().authenticated()  // Require authentication for all other requests
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // Stateless session for JWT
                .and()
                .authenticationProvider(authenticationProvider)  // Provide your custom authentication provider
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);  // Add JWT filter before username password filter

        return http.build();
    }

}
