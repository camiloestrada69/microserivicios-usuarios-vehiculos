package com.tutorial.authservice.service;

import com.tutorial.authservice.dto.AuthUserDto;
import com.tutorial.authservice.dto.TokenDto;
import com.tutorial.authservice.entity.AuthUser;
import com.tutorial.authservice.repository.AuthUserRepository;
import com.tutorial.authservice.security.JwtProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthUserService {

    @Autowired
    AuthUserRepository authUserRepository;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    JwtProvider jwtProvider;

    public AuthUser save(AuthUserDto authUserDto) {
        Optional<AuthUser> authUser = authUserRepository.findAuthUserByUsername(authUserDto.getUsername());
        if (authUser.isPresent()) {
            return null;
        }
        String password = passwordEncoder.encode(authUserDto.getPassword());
        AuthUser authUserNew = AuthUser.builder()
                .username(authUserDto.getUsername())
                .password(password)
                .build();
        return  authUserRepository.save(authUserNew);
    }

    public TokenDto login(AuthUserDto dto) {
        Optional<AuthUser> authUserOptional = authUserRepository.findAuthUserByUsername(dto.getUsername());
        if (authUserOptional.isEmpty()) {
            return null;
        }
        if (passwordEncoder.matches(dto.getPassword(), authUserOptional.get().getPassword())) {
            return new TokenDto(jwtProvider.createToken(authUserOptional.get()));
        }
        return null;

    }

    public TokenDto validate(String token) {
        if (!jwtProvider.validate(token)) {
            return null;
        }
        String username = jwtProvider.getUserNameFromToken(token);
        if (authUserRepository.findAuthUserByUsername(username).isEmpty()) {
            return null;
        }
        return new TokenDto(token);
    }
}
