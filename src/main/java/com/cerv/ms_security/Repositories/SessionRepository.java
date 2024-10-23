package com.cerv.ms_security.Repositories;

import com.cerv.ms_security.Models.Session;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface SessionRepository extends MongoRepository<Session, String> {
    @Query("{'user.$id': ObjectId(?0)}") // conecta la clase usuario buscando el identificador $id para cargar en el objectID concordando con la línea de abajo
    public List<Session> getSessionByUser(String userId); //que sesiones concuerdan con el dato del identificador
}
