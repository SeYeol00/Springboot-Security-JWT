package com.cos.jwtex01.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

   @Bean
   public CorsFilter corsFilter() {
      UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
      CorsConfiguration config = new CorsConfiguration();
      config.setAllowCredentials(true); // 내 서버가 응답할 때 json을 자바스크립트에서 처리할 수 있게 할지를 결정
      config.addAllowedOrigin("*"); // e.g. http://domain1.com 모든 ip에 응답 허용
      config.addAllowedHeader("*"); // 모든 헤더에 응답을 허용
      config.addAllowedMethod("*");// 모든 get, post put, delete, patch 요청을 허용하겠다.

      // 등록, 해당 url에서 들어오는 모든 요청은 이걸 따른다.
      source.registerCorsConfiguration("/api/**", config);
      return new CorsFilter(source);
   }

}
