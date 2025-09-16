package com.app.test;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class GeneratePass {
	
	public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String rawPassword = "tuannd";
        String encodedPassword = encoder.encode(rawPassword);
        System.out.println("BCrypt password: " + encodedPassword);
    }

}