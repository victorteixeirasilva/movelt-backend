package com.movelt.login_auth_api.controllers;

import com.movelt.login_auth_api.dtos.RegisterRequestDTO;
import com.movelt.login_auth_api.dtos.ResponseDTO;
import com.movelt.login_auth_api.domain.user.User;
import com.movelt.login_auth_api.dtos.LoginRequestDTO;
import com.movelt.login_auth_api.infra.security.TokenService;
import com.movelt.login_auth_api.respositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    @Autowired
    private final UserRepository repository;

    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Autowired
    private final TokenService tokenService;

    @RequestMapping(value = "/login", method = RequestMethod.OPTIONS)
    public ResponseEntity<Void> handlePreflight() {
        return ResponseEntity.ok()
                .header("Access-Control-Allow-Origin", "http://localhost:4200")
                .header("Access-Control-Allow-Methods", "POST, OPTIONS")
                .header("Access-Control-Allow-Headers", "Content-Type")
                .build();
    }

    @PostMapping("/login")
    private ResponseEntity<ResponseDTO> login(@RequestBody LoginRequestDTO body){
        User user = this.repository.findByEmail(body.email())
                .orElseThrow(() -> new RuntimeException("User not found"));
        if (passwordEncoder.matches(body.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new ResponseDTO(token, user.getName()));
        }
        return ResponseEntity.badRequest().build();

    }

    @PostMapping("/register")
    private ResponseEntity<ResponseDTO> register(@RequestBody RegisterRequestDTO body){
        Optional<User> user = this.repository.findByEmail(body.email());
        if (user.isEmpty()) {
            User newUser = new User();
            newUser.setName(body.name());
            newUser.setEmail(body.email());
            newUser.setPassword(passwordEncoder.encode(body.password()));
            this.repository.save(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new ResponseDTO(token, newUser.getName()));
        }
        return ResponseEntity.badRequest().build();

    }

}
