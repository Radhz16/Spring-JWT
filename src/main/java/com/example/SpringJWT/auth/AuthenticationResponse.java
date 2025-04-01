package com.example.SpringJWT.auth;


import lombok.*;
import org.springframework.data.convert.ReadingConverter;


@Builder
@NoArgsConstructor
@Data
public class AuthenticationResponse {

    private String token;

    public AuthenticationResponse(String token) {
        this.token = token;
    }

    public String getToken() {
        return token;
    }
}
