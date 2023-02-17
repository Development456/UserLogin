package com.miracle.login.repository;

import com.miracle.login.beans.PasswordResetToken;
import com.miracle.login.beans.User;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.stereotype.Repository;
@Repository
public interface PasswordResetTokenRepository extends MongoRepository<PasswordResetToken, Long> {
		  PasswordResetToken findByResetToken(String resetToken);

		  int deleteByUser(User user);
}


