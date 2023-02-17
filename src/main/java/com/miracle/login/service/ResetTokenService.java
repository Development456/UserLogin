package com.miracle.login.service;

import com.miracle.login.beans.PasswordResetToken;
import com.miracle.login.exception.TokenRefreshException;
import com.miracle.login.repository.PasswordResetTokenRepository;
import com.miracle.login.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;
@Service
public class ResetTokenService {
    @Value("${jwt.token.reset.expiration.in.seconds}")
    private Long resetTokenDurationMs;

    @Autowired
    private PasswordResetTokenRepository resetTokenRepository;

    @Autowired
    private UserRepository userRepository;

    public PasswordResetToken findByResetToken(String token) {
        return resetTokenRepository.findByResetToken(token);
    }

    public PasswordResetToken createResetToken(String string) {
        PasswordResetToken resetToken = new PasswordResetToken();

        resetToken.setUser(userRepository.findById(string).get());
        resetToken.setExpiryDate(Instant.now().plusMillis(resetTokenDurationMs));
        resetToken.setResetToken((UUID.randomUUID().toString()));

        resetToken = resetTokenRepository.save(resetToken);
        return resetToken;
    }

    public PasswordResetToken verifyExpiration(PasswordResetToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            resetTokenRepository.delete(token);
            throw new TokenRefreshException(token.getResetToken(), "Reset token was expired. Please make a new request");
        }

        return token;
    }
    @Transactional
    public int deleteByUserId(String userId) {
        return resetTokenRepository.deleteByUser(userRepository.findById(userId).get());
    }
}
