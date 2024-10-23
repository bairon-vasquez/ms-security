package com.cerv.ms_security.Controllers;

import com.cerv.ms_security.Models.Session;
import com.cerv.ms_security.Models.User;
import com.cerv.ms_security.Repositories.SessionRepository;
import com.cerv.ms_security.Repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/sessions")
public class SessionsControllers {
    @Autowired
    SessionRepository theSessionRepository;
    @Autowired
    UserRepository theUserRepository;



    @GetMapping("")
    public List<Session> find(){
        return this.theSessionRepository.findAll();
    }

    @GetMapping("/{id}")
    public Session findById(@PathVariable String id) {
        return this.theSessionRepository.findById(id).orElse(null);
    }

    @PostMapping
    public Session create(@RequestBody Session newSession){
        return this.theSessionRepository.save(newSession);
    }

    @PutMapping("/{id}")
    public Session update(@PathVariable String id, @RequestBody Session newSession){
        Session actualSession = this.theSessionRepository.findById(id).orElse(null);
        if (actualSession != null){
            actualSession.setToken(newSession.getToken());
            actualSession.setExpirationDate(newSession.getExpirationDate());
            actualSession.setUser(newSession.getUser());
            this.theSessionRepository.save(actualSession);
            return actualSession;
        }else{
            return null;
        }
    }

    @DeleteMapping({"/{id}"})
    public void delete(@PathVariable String id){
        this.theSessionRepository.findById(id).ifPresent(theSession -> this.theSessionRepository.delete(theSession));
    }

    @PostMapping("/{sessionId}/user/{userId}") //para la relación necesito que usuario es y que sesion es
    public Session matchUser(@PathVariable String sessionId, @PathVariable String userId) {
        Session theSession = this.theSessionRepository.findById(sessionId).orElse(null);
        User theUser = this.theUserRepository.findById(userId).orElse(null);

        if (theSession != null && theUser != null) {
            theSession.setUser(theUser);
            this.theSessionRepository.save(theSession);
            return theSession; //"User matched to session"; para usar este toca cambiar el metodo a String
        } else {
            return null; //"User or session not found";

        }
    }

    @GetMapping("/user/{userId}") //cuando se llama manda el identificador de usuairo y filtra todas las sesiones de ese usuario
    public List<Session> getSessionByUser(@PathVariable String userId){
        return this.theSessionRepository.getSessionByUser(userId);
    }
}