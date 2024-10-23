package com.cerv.ms_security.Controllers;

import com.cerv.ms_security.Models.*;
import com.cerv.ms_security.Repositories.SessionRepository;
import com.cerv.ms_security.Repositories.UserRepository;
import com.cerv.ms_security.Repositories.UserRoleRepository;
import com.cerv.ms_security.Services.EncryptionService;
import com.cerv.ms_security.Services.MailSenderRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import com.cerv.ms_security.Services.JwtService;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@CrossOrigin
@RestController
@RequestMapping("/api/public/security")
public class SecurityController {
    @Autowired
    private UserRepository theUserRepository; //hacemos el login
    @Autowired
    private EncryptionService theEncryptionService; //el usuario que quiere autenticarso mando su contraseña, así verificamos que la contraseña que esta mandnado en el login sea igual a la encriptada
    @Autowired
    private JwtService theJwtService; //toda la información del usuario en caso de que el login sea exitoso
    @Autowired
    private SessionRepository theSessionRepository;

    @Autowired
    private MailSenderRequest theMailSenderRequest;

    @Autowired
    private UserRoleRepository theUserRoleRepository;

//    @PostMapping("/login")
//    public HashMap<String,Object> login(@RequestBody User theNewUser,
//                                        final HttpServletResponse response)throws IOException {
//        HashMap<String,Object> theResponse=new HashMap<>();
//        String token="";
//        User theActualUser=this.theUserRepository.getUserByEmail(theNewUser.getEmail());
//        if(theActualUser!=null &&
//           theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))){
//            token=theJwtService.generateToken(theActualUser);
//            theActualUser.setPassword("");
//            theResponse.put("token",token);
//            //theResponse.put("user",theActualUser); //de esta manera al comentarlo solo nos devolvera el token
//            return theResponse;
//        }else{
//            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
//            return  theResponse;
//        }
//
//    }

    @PostMapping("/login")
    public HashMap<String, Object> login(@RequestBody User theNewUser,
                                         final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if (theActualUser != null &&
                theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))) {

            String twoFactorCode = theEncryptionService.validationCode();

            List<Session> theSessions = theSessionRepository.getSessionByUser(theActualUser.get_id());
            theSessions.forEach(session -> {
                session.setCodeValidation(twoFactorCode);
            });
            theSessionRepository.saveAll(theSessions);

            theActualUser.setPassword("");
            theResponse.put("user", theActualUser);

            try {
                theMailSenderRequest.twoFactorEmail(twoFactorCode, theActualUser.getEmail(), theActualUser.getName());
            } catch (Exception e) {
                e.printStackTrace();
            }
        } else {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        }
        return theResponse;
    }

    
    @PostMapping("/login/validate/{twoFactorCode}")
    public HashMap<String, Object> validateLogin(@RequestBody User theNewUser, @PathVariable String twoFactorCode,
                                                 final HttpServletResponse response) throws IOException {
        HashMap<String, Object> theResponse = new HashMap<>();
        String tokenResponse;
        User theActualUser = this.theUserRepository.getUserByEmail(theNewUser.getEmail());
        if (theActualUser != null &&
                theActualUser.getPassword().equals(theEncryptionService.convertSHA256(theNewUser.getPassword()))
                && this.twoFactorValidation(theActualUser, twoFactorCode)) {

            tokenResponse = theJwtService.generateToken(theActualUser);

            List<Session> theSessions = theSessionRepository.getSessionByUser(theActualUser.get_id());
            theSessions.forEach(session -> {
                session.setCodeValidation("");
                session.setToken(tokenResponse);
            });
            theSessionRepository.saveAll(theSessions);

            theActualUser.setPassword("");
            theResponse.put("user", theActualUser);
            theResponse.put("token", tokenResponse);
        } else {

            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);

        }
        return theResponse;
    }

    private boolean twoFactorValidation(User theActualUser, String twoFactorCode) {
        List<Session> theSessions = theSessionRepository.getSessionByUser(theActualUser.get_id());
        for (Session session : theSessions) {
            if (session.getCodeValidation().equals(twoFactorCode)) {
                return true;
            }
        }
        return false;
    }
    

    @GetMapping("/most-used-role")
    public Map<Role, Long> getMostUsedRole() {
        List<Session> theSessions = theSessionRepository.findAll();
        Map<Role, Long> roleSessionCount = new HashMap<>();
        theSessions.forEach(session -> {
            User theUser = session.getUser();
            if (theUser != null) {
                List<UserRole>theUserRoles = this.theUserRoleRepository.getRolesByUserId(theUser.get_id());
                for (UserRole userRole : theUserRoles) {
                    Role theRole = userRole.getRole(); // Obtener el rol de cada relación
                    roleSessionCount.put(theRole, roleSessionCount.getOrDefault(theRole, 0L) + 1);
                }
            }
        });

        return roleSessionCount;
    }


}
