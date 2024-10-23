package com.cerv.ms_security.Services;


import com.cerv.ms_security.Models.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
@Service
public class JwtService {
    @Value("${jwt.secret}")
    private String secret; // Esta es la clave secreta que se utiliza para firmar el token. Debe mantenerse segura.

    @Value("${jwt.expiration}")
    private Long expiration; // Tiempo de expiración del token en milisegundos.
    private Key secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    public String generateToken(User theUser) {
        Date now = new Date(); // tomo la hora actual
        Date expiryDate = new Date(now.getTime() + expiration); // calculo la fecha de expiración
        Map<String, Object> claims = new HashMap<>(); //diccionario claims, todos los datos que quiero que vayan dentro del token
        claims.put("_id", theUser.get_id());
        claims.put("name", theUser.getName());
        claims.put("email", theUser.getEmail());

        return Jwts.builder() //dentro del token ponga todo el diccionario que se armo arriba
                .setClaims(claims)
                .setSubject(theUser.getName())
                .setIssuedAt(now) //cuando se genero el token
                .setExpiration(expiryDate) //la expiración
                .signWith(secretKey) //como los token pueden ser modificados, firmo el token, de esa manera se genera la cadena larga
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);

            // Verifica la expiración del token
            Date now = new Date();
            if (claimsJws.getBody().getExpiration().before(now)) {
                return false;
            }

            return true;
        } catch (SignatureException ex) {
            // La firma del token es inválida
            return false;
        } catch (Exception e) {
            // Otra excepción
            return false;
        }
    }

    public User getUserFromToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey) //verifica si el token fue firmado
                    .build()
                    .parseClaimsJws(token); //da la cadena larga(token) vuelve a obtener los datos

            Claims claims = claimsJws.getBody(); //proceso de conversión

            User user = new User();
            user.set_id((String) claims.get("_id"));
            user.setName((String) claims.get("name"));
            user.setEmail((String) claims.get("email"));
            return user;
        } catch (Exception e) {
            // En caso de que el token sea inválido o haya expirado
            return null;
        }
    }


}
