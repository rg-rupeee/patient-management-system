package com.rupesh.auth_service.service;

import com.rupesh.auth_service.dto.LoginRequestDTO;
import com.rupesh.auth_service.model.User;
import com.rupesh.auth_service.util.JwtUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthService {
	private final UserService userService;
	private final PasswordEncoder passwordEncoder;
	private final JwtUtil jwtUtil;

	public AuthService(UserService userService, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
		this.userService = userService;
		this.passwordEncoder = passwordEncoder;
		this.jwtUtil = jwtUtil;
	}

	public Optional<String> authenticate(LoginRequestDTO loginRequestDTO){
		return userService
				.findByEmail(loginRequestDTO.getEmail())
				.filter(u -> passwordEncoder.matches(loginRequestDTO.getPassword(), u.getPassword()))
				.map(u -> jwtUtil.generateToken(u.getEmail(), u.getRole()));
	}

	public boolean validateToken(String token){
		try{
			jwtUtil.validateToken(token);
			return true;
		} catch (JwtException e){
			return false;
		}
	}
}
