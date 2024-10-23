package com.cerv.ms_security.Controllers;

import com.cerv.ms_security.Models.Role;
import com.cerv.ms_security.Models.User;
import com.cerv.ms_security.Models.UserRole;
import com.cerv.ms_security.Repositories.RoleRepository;
import com.cerv.ms_security.Repositories.UserRepository;
import com.cerv.ms_security.Repositories.UserRoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/user_role")

public class UserRoleControllers {
    @Autowired
    UserRepository theUserRepository;

    @Autowired
    RoleRepository theRoleRepository;

    @Autowired
    UserRoleRepository theUserRoleRepository;

    @PostMapping ("user/{userId}/role/{roleId}") // post create
    public UserRole create( @PathVariable String userId, @PathVariable String roleId){ // nuevo usuario, @ dentro del cuerpo de la petición  se va a leer el json y va a ser casteado a un usuario en java en este caso newUser
        User theUser = this.theUserRepository.findById(userId).orElse(null);
        Role theRole = this.theRoleRepository.findById(roleId).orElse(null);
        if (theUser != null && theRole!= null) {
            UserRole newUserRole = new UserRole();
            //Enlaces de relacion N-N
            newUserRole.setUser(theUser);
            newUserRole.setRole(theRole);
            this.theUserRoleRepository.save(newUserRole);
            return newUserRole;
        }
        return  null;
    }
    @GetMapping ("user/{userId}")
    public List<UserRole> getRolesByUser(@PathVariable String userId){
        return this.theUserRoleRepository.getRolesByUser(userId);
    }

    @GetMapping ("role/{roleId}")
    public List<UserRole> getUsersByRole(@PathVariable String roleId){
        return this.theUserRoleRepository.getUsersByRole(roleId);
    }



    @DeleteMapping("{id}") //petición para borrar, usando el identificador
    public void delete(@PathVariable String id){ //lee el identificador que va en la ruta
        User theUser = this.theUserRepository.findById(id).orElse(null); //busca el usuario por identeificador si no devuelva null
        if (theUser != null){
            this.theUserRepository.delete(theUser); //si es diferente de nullo o sea si existe, elimine el usuario
        }
    }
}