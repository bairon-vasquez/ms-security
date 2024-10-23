package com.cerv.ms_security.Controllers;

import com.cerv.ms_security.Models.User;
import com.cerv.ms_security.Repositories.UserRepository;
import com.cerv.ms_security.Services.EncryptionService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@CrossOrigin
@RestController
@RequestMapping("/api/users")

public class UsersControllers {
    @Autowired
    UserRepository theUserRepository;

    @Autowired
    EncryptionService theEncryptionService;

    @GetMapping("")
    public List<User> find(){
        return this.theUserRepository.findAll(); //el findAll() enlista todos los elementos
    }

//    @GetMapping({"id"})//obtengo el identificador que viene en la ruta
//    public User findById(@PathVariable String id){ //devuelve un usuario de la clase usuario en json, el @para decir que viene una variable en la ruta de tipo string
//        User theUser = this.theUserRepository.findById(id).orElse(null); // usuario que devuelve, diciendole al repositorio que lo busque por el identificador que llego en la línea anterior, sino encuentra nada retorna un usuario null
//        return theUser;
//    }

    @GetMapping("/{id}")
    public User findById(@PathVariable String id){ //devuelve un usuario de la clase usuario en json, el @para decir que viene una variable en la ruta de tipo string
        return this.theUserRepository.findById(id).orElse(null); // un usuario que devuelve, diciendole al repositorio que lo busque por el identificador que llego en la línea anterior, sino encuentra nada retorna un usuario null
    }

    @PostMapping // post crear
    public User create(@RequestBody User newUser){ // nuevo usuario, @ dentro del cuerpo de la petición  se va a leer el json y va a ser casteado a un usuario en java en este caso newUser
        newUser.setPassword(this.theEncryptionService.convertSHA256(newUser.getPassword())); //al nuevo usuario le cambio la nueva contraseña con lo que viene cifrado
        return this.theUserRepository.save(newUser); // le dice al repositorio que haga un almacenamiento del usuario
    }

    @PutMapping("/{id}")
    public User update(@PathVariable String id, @RequestBody User newUser){ //identificador del elemento y contenido del elemento que quiero actualizar
        User actualUser = this.theUserRepository.findById(id).orElse(null); //busca el usuario
        if (actualUser != null){ // si es diferente de null
            actualUser.setName(newUser.getName()); //modifica su nombre
            actualUser.setEmail(newUser.getEmail()); //modifica su correo
            actualUser.setPassword(this.theEncryptionService.convertSHA256(actualUser.getPassword())); //modifica su contraseña
            this.theUserRepository.save(actualUser);
            return actualUser;
        }else{
            return null;
        }
    }

    @DeleteMapping("/{id}") //petición para borrar, usando el identificador
    public void delete(@PathVariable String id){ //lee el identificador que va en la ruta
        User theUser = this.theUserRepository.findById(id).orElse(null); //busca el usuario por identeificador si no devuelva null
        if (theUser != null){
            this.theUserRepository.delete(theUser); //si es diferente de nullo o sea si existe, elimine el usuario
        }
    }


}
