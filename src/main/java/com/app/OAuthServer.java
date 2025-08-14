package com.app;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisIndexedHttpSession;

@SpringBootApplication
@EnableRedisIndexedHttpSession
public class OAuthServer {
    public static void main(String[] args) {
       SpringApplication.run(OAuthServer.class, args);
    }
}