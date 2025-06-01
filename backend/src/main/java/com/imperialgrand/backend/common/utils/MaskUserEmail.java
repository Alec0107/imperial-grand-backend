package com.imperialgrand.backend.common.utils;

public class MaskUserEmail {
    public static String maskUserEmail(String email) {
        StringBuilder sb = new StringBuilder();
        boolean reachedAt = false;

        for(int i = 0; i < email.length(); i++){
            char c = email.charAt(i);

            if(c == '@'){
                reachedAt = true;
            }

            if(i < 1 || reachedAt){
                sb.append(c);
            }else{
                sb.append('*');
            }
        }
        return sb.toString();
    }
}
