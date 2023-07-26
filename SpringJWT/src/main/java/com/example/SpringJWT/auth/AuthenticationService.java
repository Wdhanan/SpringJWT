package com.example.SpringJWT.auth;

import com.example.SpringJWT.config.JwtService;
import com.example.SpringJWT.user.Role;
import com.example.SpringJWT.user.User;
import com.example.SpringJWT.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    // inject UserRepository
    @Autowired
    private UserRepository userRepository;
    private final PasswordEncoder passWordEncoder; // injection to encode our password
    private final JwtService jwtService;// injection to generate a Token

    private final AuthenticationManager authenticationManager;// do all our Job for the Authentification


    // return an AuthentificationResponse which contains the Token
    public AuthenticationResponse register( RegisterRequest registerRequest){
        var user= User.builder()
                .firstname(registerRequest.getFirstname())
                .lastname(registerRequest.getLastname())
                .email(registerRequest.getEmail())
                .password(passWordEncoder.encode(registerRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);// Transfering the user to our Database
        var jwtToken= jwtService.generateToken(user);
        return  AuthenticationResponse.builder()
                        .token(jwtToken)
                .build();



    }


    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );// authentification successfull
        var user= userRepository.findByEmail(request.getEmail())
                .orElseThrow();
        //generation of the Token
        var jwtToken= jwtService.generateToken(user);
        return  AuthenticationResponse.builder()
                .token(jwtToken)
                .build();


    }
}
