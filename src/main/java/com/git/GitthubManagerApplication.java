package com.git;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

@SpringBootApplication(exclude = {DataSourceAutoConfiguration.class })
public class GitthubManagerApplication {

	public static void main(String[] args) {
		SpringApplication.run(GitthubManagerApplication.class, args);
	}

}
