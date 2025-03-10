package com.example.apigatewayshop;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
//@EnableDiscoveryClient
public class ApiGatewayShopApplication {

	public static void main(String[] args) {
		SpringApplication.run(ApiGatewayShopApplication.class, args);
	}

}
