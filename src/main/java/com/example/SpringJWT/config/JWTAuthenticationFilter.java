package com.example.SpringJWT.config;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.util.Base64URL;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.text.ParseException;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;  // Your JWT service for extracting claims
    private final UserDetailsService userDetailsService;

    public JWTAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // Check if Authorization header is present and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);  // Proceed with the next filter
            return;
        }

        // Extract JWT token from Authorization header
        jwt = authHeader.substring(7);

        try {
            // Use Nimbus JOSE + JWT to parse and verify the JWT
            SignedJWT signedJWT = SignedJWT.parse(jwt);

            // Verify the JWT signature (using the same secret that was used to sign it)
            MACVerifier verifier = new MACVerifier(jwtService.getSecretKey());
            if (signedJWT.verify(verifier)) {

                // Extract the user email from the token
                JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
                userEmail = claims.getSubject();

                // Proceed if the JWT is valid and the user is not already authenticated
                if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                    // Create an authentication token and set the details
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set the authentication token in the security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            } else {
                throw new SecurityException("Invalid JWT signature");
            }

        } catch (ParseException | SecurityException | JOSEException e) {
            // If JWT parsing or verification fails, reject the request (log the error if needed)
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        /
