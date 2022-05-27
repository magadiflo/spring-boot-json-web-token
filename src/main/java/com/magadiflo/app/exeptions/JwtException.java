package com.magadiflo.app.exeptions;

public class JwtException extends RuntimeException {
    public JwtException(String message){
        System.out.println(message);
    }
}
