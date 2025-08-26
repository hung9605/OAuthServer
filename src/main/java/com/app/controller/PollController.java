package com.app.controller;

import com.zaxxer.hikari.HikariDataSource;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/poll")
public class PollController {

    private final HikariDataSource dataSource;

    public PollController(HikariDataSource dataSource) {
        this.dataSource = dataSource;
    }


    /**
     * Soft refresh HikariCP pool: đóng các connection cũ khi hết hạn,
     * pool sẽ tự tạo connection mới.
     */
    @GetMapping("/refresh")
    public String refreshPool() {
        try {
            dataSource.getHikariPoolMXBean().softEvictConnections();
            return "HikariCP pool refreshed successfully!";
        } catch (Exception e) {
            return "Failed to refresh pool: " + e.getMessage();
        }
    }

}
