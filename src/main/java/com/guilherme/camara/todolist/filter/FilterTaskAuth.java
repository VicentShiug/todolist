package com.guilherme.camara.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.guilherme.camara.todolist.user.IUserRepository;

import at.favre.lib.crypto.bcrypt.BCrypt;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var serveltPath = request.getServletPath();

        if (serveltPath.startsWith("/tasks/")) {

            // Pegar a autentiação (usuário e senha)
            var authorization = request.getHeader("Authorization");

            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecode = Base64.getDecoder().decode(authEncoded);

            var authString = new String(authDecode);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            // Validar usuário
            var user = this.userRepository.findByUsername(username);
            if (user == null) {
                response.sendError(401);
            } else {

                // Validar senha
                var passwordVarify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (passwordVarify.verified) {
                    request.setAttribute("idUser", user.getId());
                    filterChain.doFilter(request, response); // segue a vida boy
                } else {
                    response.sendError(401);
                    // Seguir viagem hheheeheh boyyyyyyyyyyyyy
                }

            }
        } else {
            filterChain.doFilter(request, response); // segue a vida boy
        }
    }
}
