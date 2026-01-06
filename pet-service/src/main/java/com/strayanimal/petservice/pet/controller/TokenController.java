package com.strayanimal.petservice.pet.controller;

import com.strayanimal.petservice.common.auth.JwtTokenProvider;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class TokenController {

    private final JwtTokenProvider tokenProvider;

    @GetMapping("/issue")
    public ResponseEntity<?> issueToken(HttpServletRequest request) {

        String ip = request.getRemoteAddr();
        String userAgent = request.getHeader("User-Agent");

        // 1️⃣ 최소 검증
        if (userAgent == null || userAgent.isBlank()) {
            return ResponseEntity.status(403).build();
        }

        // 2️⃣ 토큰 발급
        String token = tokenProvider.createAnonymousToken(ip, userAgent);

        return ResponseEntity.ok(token);
    }

}
