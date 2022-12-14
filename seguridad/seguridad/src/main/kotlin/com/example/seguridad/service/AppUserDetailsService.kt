package com.example.seguridad.service

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.stereotype.Service

@Service
class AppUserDetailsService : UserDetailsService {
    override fun loadUserByUsername(username: String?): UserDetails {
        return User("user","{noop}admin", ArrayList())
    }

}