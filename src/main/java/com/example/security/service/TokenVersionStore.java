package com.example.security.service;

import org.springframework.stereotype.Service;

import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenVersionStore {

    private ConcurrentHashMap<Integer, Integer> tokenVersions = new ConcurrentHashMap<>();

    public int getCurrentVersion(int userId) {
        return tokenVersions.getOrDefault(userId, 0);
    }

    public void incrementVersion(int userId) {
        tokenVersions.put(userId, getCurrentVersion(userId) + 1);
    }

}
