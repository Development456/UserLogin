package com.miracle.login.jwt.payload;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PasswordRequest {
	private String username;
	private String currentPassword;
	private String newPassword;
}
