package com.example.jobportal.service;

import com.example.jobportal.entity.User;
import com.example.jobportal.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private EmailService emailService;
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    // In-memory map to store OTPs with expiration (email -> OTPInfo)
    private final Map<String, OTPInfo> otpStore = new HashMap<>();
    
    // OTP expiration time in minutes
    private static final int OTP_EXPIRATION_MINUTES = 10;

    private static class OTPInfo {
        String otp;
        Instant expirationTime;
        
        OTPInfo(String otp) {
            this.otp = otp;
            this.expirationTime = Instant.now().plusSeconds(OTP_EXPIRATION_MINUTES * 60);
        }
        
        boolean isExpired() {
            return Instant.now().isAfter(expirationTime);
        }
    }

    public String signup(User user) {
        if (userRepository.findByEmail(user.getEmail()) != null) {
            return "Email already exists";
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setVerified(false);
        user.setAppliedJobs(new java.util.ArrayList<>());
        userRepository.save(user);

        String otp = String.format("%06d", new Random().nextInt(999999));
        otpStore.put(user.getEmail(), new OTPInfo(otp)); // Store the generated OTP with expiration
        emailService.sendOtp(user.getEmail(), otp);
        return "OTP sent to email";
    }

    public String verifyEmail(String email, String otp) {
        System.out.println("Verifying OTP for email: " + email + ", OTP: " + otp);
        
        OTPInfo otpInfo = otpStore.get(email);
        if (otpInfo == null) {
            System.out.println("No OTP found for email: " + email);
            return "Invalid OTP";
        }
        
        if (otpInfo.isExpired()) {
            System.out.println("OTP expired for email: " + email);
            otpStore.remove(email);
            return "OTP expired";
        }
        
        if (otpInfo.otp.equals(otp)) {
            User user = userRepository.findByEmail(email);
            if (user != null) {
                user.setVerified(true);
                userRepository.save(user);
                otpStore.remove(email); // Clear OTP after successful verification
                System.out.println("OTP verified successfully for email: " + email);
                return "Verified";
            }
        }
        
        System.out.println("Invalid OTP provided for email: " + email);
        return "Invalid OTP";
    }

    public User login(String email, String password) {
        System.out.println("Login attempt for email: " + email);
        
        User user = userRepository.findByEmail(email);
        if (user == null) {
            System.out.println("User not found for email: " + email);
            return null;
        }
        
        if (!user.isVerified()) {
            System.out.println("User not verified for email: " + email);
            return null;
        }
        
        if (!passwordEncoder.matches(password, user.getPassword())) {
            System.out.println("Invalid password for email: " + email);
            return null;
        }
        
        System.out.println("Login successful for email: " + email);
        return user;
    }

    public void applyJob(Long userId, Long jobId) {
        User user = userRepository.findById(userId).orElseThrow();
        user.getAppliedJobs().add(jobId);
        userRepository.save(user);
    }

    public User getUserById(Long id) {
        return userRepository.findById(id).orElse(null);
    }
    
    // Method to resend OTP
    public String resendOtp(String email) {
        User user = userRepository.findByEmail(email);
        if (user == null) {
            return "User not found";
        }
        
        if (user.isVerified()) {
            return "User already verified";
        }
        
        String otp = String.format("%06d", new Random().nextInt(999999));
        otpStore.put(email, new OTPInfo(otp));
        emailService.sendOtp(email, otp);
        return "New OTP sent to email";
    }
    
    // Debug method to check current state
    public String debugUsers() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== DEBUG INFO ===\n");
        sb.append("Total users in database: ").append(userRepository.count()).append("\n");
        sb.append("OTPs in memory: ").append(otpStore.size()).append("\n");
        
        for (Map.Entry<String, OTPInfo> entry : otpStore.entrySet()) {
            sb.append("Email: ").append(entry.getKey())
              .append(", OTP: ").append(entry.getValue().otp)
              .append(", Expires: ").append(entry.getValue().expirationTime)
              .append(", Expired: ").append(entry.getValue().isExpired())
              .append("\n");
        }
        
        return sb.toString();
    }
}