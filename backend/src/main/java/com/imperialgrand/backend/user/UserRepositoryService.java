package com.imperialgrand.backend.user;

import com.imperialgrand.backend.user.exception.EmailAlreadyUsedException;
import com.imperialgrand.backend.user.exception.EmailNotFoundException;
import com.imperialgrand.backend.user.exception.EmailNotVerifiedException;
import com.imperialgrand.backend.user.model.User;
import com.imperialgrand.backend.user.repository.UserRepository;
import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Data
@Builder
@Repository
public class UserRepositoryService {

    private final UserRepository userRepository;

    public User getUserByEmail(String email){
        return userRepository.findByEmail(email)
                .orElseThrow(()-> new EmailNotFoundException("Email not found"));
    }

    // for password reset just return null if no user object as saved
    public User getUserByEmailForPassReset(String email){
        return userRepository.findByEmail(email).orElse(null);
    }


    public boolean isUserEnabled(User user){
        if(user.isEnabled()){
            return true;
        }else{
            throw new EmailNotVerifiedException("Email is not verified");
        }
    }

    public void isEmailAvailable(String email){
        Optional<User> user = userRepository.findByEmail(email);
        if(user.isPresent()){
            throw new EmailAlreadyUsedException("Email is already in use");
        }
    }

    public void saveUser(User user){
        userRepository.save(user);
    }
}
