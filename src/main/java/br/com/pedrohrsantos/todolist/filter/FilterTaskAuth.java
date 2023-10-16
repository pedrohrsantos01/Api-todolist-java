package br.com.pedrohrsantos.todolist.filter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.pedrohrsantos.todolist.user.IUserRepository;
import br.com.pedrohrsantos.todolist.user.UserModel;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Base64;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var servletPath = request.getServletPath();
        if (servletPath.startsWith("/tasks/")) {
            var authorization = request.getHeader("Authorization");

            var authEncoded = authorization.substring("Basic".length()).trim();

            byte[] authDecoded = Base64.getDecoder().decode(authEncoded);

            String authString = new String(authDecoded);

            String[] credentials = authString.split(":");
            String username = credentials[0];
            String password = credentials[1];

            var usuario = this.userRepository.findByUsername(username);
            if (usuario == null) {
                response.sendError(401, "Usuário sem autorização");
            } else {
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), usuario.getPassword());
                if (passwordVerify.verified) {
                    request.setAttribute("idUser", usuario.getId());
                    filterChain.doFilter(request, response);
                } else {
                    response.sendError(401);
                }
            }
        } else {
            filterChain.doFilter(request, response);
        }


    }
}
