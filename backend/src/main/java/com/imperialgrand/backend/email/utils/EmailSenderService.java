package com.imperialgrand.backend.email.utils;

import com.imperialgrand.backend.auth.dto.RegisterRequest;
import com.imperialgrand.backend.user.model.User;
import com.imperialgrand.backend.common.utils.MaskUserEmail;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailSenderService {


    @Value("${spring.mail.username}")
    private String sender;

    private final JavaMailSender mailSender;

    private final String ResetURL = "http://localhost:5500/pages/forgot-password/reset-password.html";


    public String sendSimpleEmailVerif(RegisterRequest registerRequest, String token, int tokenId) {
       return sendVerificationEmail(registerRequest.getEmail(), registerRequest.getFirstName(), token, tokenId);
    }

    public String resendSimpleEmailVerif(User user, String token, int tokenId){
        return sendVerificationEmail(user.getEmail(), user.getFirstName(), token, tokenId);
    }

    private String sendVerificationEmail(String toEmail, String firstName, String token, int tokenId) {

        try{
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(sender);
            message.setTo(toEmail);
            message.setSubject("[Imperial Grand] Verify Your Imperial Grand Account");
            message.setText("Hi, " + firstName + "\n\n" +
                            "Welcome to Imperial Grand Cantonese Restaurant! \n" +
                            "To finish your registration, please verify your email by clicking this link: \n" +
                             "http://192.168.0.112:8080/api/v1/auth/verify?token=" + token + "&id=" + tokenId + "\n\n" +
                            "Unable to click the link above? You can also copy and past the link into your browser " +
                            "address bar and press Enter to complete the verification");

            mailSender.send(message);

            String maskedEmail = MaskUserEmail.maskUserEmail(toEmail);
            // response back to frontend
            String msg = "We sent a verification email link to " + maskedEmail + ". Please verify email to activate your account.";


            System.out.println("Email sent successfully to " + toEmail);
            System.out.println(maskedEmail);
            return msg;

        }catch (Exception ex){
            System.out.println(ex.getMessage());
            throw new RuntimeException(ex);
        }

    }


    public String sendResetPasswordEmail(String toEmail, String firstName, String token, int tokenId) {
        String msg = null;
        try{
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(sender);
            message.setTo(toEmail);
            message.setSubject("[Imperial Grand] Reset Your Password");
            message.setText("Hi " + firstName + ",\n" +
                    "\n" +
                    "We received a request to reset the password for your account.\n" +
                    "\n" +
                    "Click the link below to reset your password:\n" +
                    "\n" +
                    ResetURL + "?token=" + token + "&id=" + tokenId +"\n" +
                    "\n" +
                    "If you did not request this, you can safely ignore this email — your password will remain unchanged.\n" +
                    "\n" +
                    "This link will expire in 15 minutes for your security.\n" +
                    "\n" +
                    "Thanks,  \n" +
                    "The Imperial Grand Team");

            mailSender.send(message);
            String maskedEmail = MaskUserEmail.maskUserEmail(toEmail);

            msg = "If an account exists for " + maskedEmail +", a password reset link has been sent.";
        }catch (Exception ex){
            System.out.println(ex.getMessage());
        }

        return msg;
    }


}
