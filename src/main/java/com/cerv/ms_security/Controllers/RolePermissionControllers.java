package com.cerv.ms_security.Controllers;

import com.cerv.ms_security.Models.*;
import com.cerv.ms_security.Repositories.PermissionRepository;
import com.cerv.ms_security.Repositories.RolePermissionRepository;
import com.cerv.ms_security.Repositories.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/role-permission")

public class RolePermissionControllers {
    @Autowired
    RoleRepository theRoleRepository;

    @Autowired
    PermissionRepository thePermissionRepository;

    @Autowired
    RolePermissionRepository theRolePermissionRepository;

    @GetMapping("")
    public List<RolePermission> find(){
        return this.theRolePermissionRepository.findAll();
    }

    @PostMapping ("role/{roleId}/permission/{permissionId}") // post create
    public RolePermission create(@PathVariable String roleId, @PathVariable String permissionId){ // nuevo usuario, @ dentro del cuerpo de la petición  se va a leer el json y va a ser casteado a un usuario en java en este caso newUser
        Role theRole = this.theRoleRepository.findById(roleId).orElse(null);
        Permission thePermission = this.thePermissionRepository.findById(permissionId).orElse(null);
        if (theRole != null && thePermission!= null) {
            RolePermission newRolePermission = new RolePermission();
            //Enlaces de relacion N-N
            newRolePermission.setRole(theRole);
            newRolePermission.setPermission(thePermission);
            this.theRolePermissionRepository.save(newRolePermission);
            return newRolePermission;
        }
        return  null;
    }

    @GetMapping ("role/{roleId}")
    public List<RolePermission> getPermissionsByRole(@PathVariable String roleId){
        return this.theRolePermissionRepository.getPermissionsByRole(roleId);
    }

    @GetMapping ("permission/{permissionId}")
    public List<UserRole> getRolePermission(@PathVariable String permissionId){
        return (List<UserRole>) this.getRolePermission(permissionId);
    }

    @DeleteMapping("{id}") //petición para borrar, usando el identificador
    public void delete(@PathVariable String id){ //lee el identificador que va en la ruta
        Role theRole = this.theRoleRepository.findById(id).orElse(null); //busca el usuario por identeificador si no devuelva null
        if (theRole != null){
            this.theRoleRepository.delete(theRole); //si es diferente de nullo o sea si existe, elimine el usuario
        }
    }
}
