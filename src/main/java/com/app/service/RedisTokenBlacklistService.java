package com.app.service;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
public class RedisTokenBlacklistService {
	
	    private final RedisTemplate<String, String> redisTemplate;
	    public RedisTokenBlacklistService(RedisTemplate<String, String> redisTemplate) {
	        this.redisTemplate = redisTemplate;
	    }
	    public void blacklist(String tokenValue, long ttlSeconds) {
	        redisTemplate.opsForValue().set(tokenValue, "revoked", Duration.ofSeconds(ttlSeconds));
	    }
	    public boolean isBlacklisted(String tokenValue){
	        return Boolean.TRUE.equals(redisTemplate.hasKey(tokenValue));
	    }

}
