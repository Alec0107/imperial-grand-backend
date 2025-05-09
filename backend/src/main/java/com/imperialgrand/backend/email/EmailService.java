package com.imperialgrand.backend.email;

import com.imperialgrand.backend.dto.RegisterRequest;
import com.imperialgrand.backend.user.User;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailService {

    private final JavaMailSender mailSender;
    @Value("${spring.mail.username}")
    private String sender;


    public String sendSimpleEmailVerif(RegisterRequest registerRequest, String token, int tokenId) {
       return sendSimpleEmail(registerRequest.getEmail(), registerRequest.getFirstName(), token, tokenId);
    }

    public String resendSimpleEmailVerif(User user, String token, int tokenId){
        return sendSimpleEmail(user.getEmail(), user.getFirstName(), token, tokenId);
    }


    public String sendSimpleEmail(String toEmail, String firstName, String token, int tokenId) {

        try{
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(sender);
            message.setTo(toEmail);
            message.setSubject("Verify Your Imperial Grand Account");
            message.setText("Hi, " + firstName + "\n\n" +
                            "Welcome to Imperial Grand Cantonese Restaurant! \n" +
                            "To finish your registration, please verify your email by clicking this link: \n" +
                             "http://192.168.0.112:8080/api/v1/auth/verify?token=" + token + "&id=" + tokenId + "\n\n" +
                            "Unable to click the link above? You can also copy and past the link into your browser " +
                            "address bar and press Enter to complete the verification");

            mailSender.send(message);

            System.out.println("Email sent successfully to " + toEmail);
            return "We sent a verification email link to " + toEmail;
        }catch (Exception ex){
            System.out.println(ex.getMessage());
            throw new RuntimeException(ex);
        }

    }

}
