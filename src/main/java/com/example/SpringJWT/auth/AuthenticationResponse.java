package com.example.SpringJWT.auth;


import lombok.*;
import org.springframework.data.convert.ReadingConverter;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {

    private String token;
}
