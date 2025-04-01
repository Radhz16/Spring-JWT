package com.example.SpringJWT.config;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.MACVerifier;

import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;

public class JwtService {

    private static final String SECRET_KEY = "your-secret-key";

    // Replace with your actual secret key
    public byte[] getSecretKey() {
        return SECRET_KEY.getBytes(StandardCharsets.UTF_8);
    }

    // Method to parse the JWT token and extract claims
    public JWTClaimsSet extractClaims(String token) throws ParseException {
        // Parse the JWT token
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Verify the signature (using the secret key)
        MACVerifier verifier = new MACVerifier(SECRET_KEY);
        if (signedJWT.verify(verifier)) {
            // Extract and return the claims
            return signedJWT.getJWTClaimsSet();
        } else {
            throw new SecurityException("Invalid JWT signature");
        }
    }

    // Method to extract a specific claim from the JWT
    public String extractUsername(String token) throws ParseException {
        JWTClaimsSet claims = extractClaims(token);
        return claims.getSubject();  // This is usually the "username"
    }

    // Method to check if the JWT has expired
    public boolean isTokenExpired(String token) throws ParseException {
        JWTClaimsSet claims = extractClaims(token);
        Date expiration = claims.getExpirationTime();
        return expiration.before(new Date());  // Check if current time is after expiration time
    }

    // Example method to validate a token
    public boolean isTokenValid(String token, String username) throws ParseException {
        String extractedUsername = extractUsername(token);
        return extractedUsername.equals(username) && !isTokenExpired(token);
    }
}
