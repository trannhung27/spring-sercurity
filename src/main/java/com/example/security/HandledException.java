package com.example.security;

public class HandledException extends Exception{
    String message;

    public HandledException(String message){
        this.message = message;
    }
}
