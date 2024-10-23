package com.cerv.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;


@Data //para que guarde esa clase en persistencia, se almacena en una base de datos
@Document //de mongo, como quiere lo que se llame la tabla en la base de datos, toma el nombre por defecto del usuario

public class UserRole {
    @Id
    private String _id;
    @DBRef
    private User user;
    @DBRef
    private Role role;

    public UserRole(){

    }

    public String get_id() {
        return _id;
    }

    public void set_id(String _id) {
        this._id = _id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
