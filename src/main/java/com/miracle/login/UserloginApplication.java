package com.miracle.login;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@Slf4j
@SpringBootApplication
public class UserloginApplication {

	public static void main(String[] args) {
		try{
			SpringApplication.run(UserloginApplication.class, args);
		}catch (Throwable e) {
            if(e.getClass().getName().contains("SilentExitException")) {
            	// skipping for spring known bug https://github.com/spring-projects/spring-boot/issues/3100
                log.debug("Spring is restarting the main thread - See spring-boot-devtools");
            } else {
                throw e;
            }
		}

	}
}