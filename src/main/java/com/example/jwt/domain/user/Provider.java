package com.example.jwt.domain.user;

public enum Provider {
    LOCAL("local"), GOOGLE("google"), GITHUB("github");
    public final String provider;
    Provider(String provider) {
        this.provider = provider;
    }
}