package com.cerv.ms_security.Repositories;

import com.cerv.ms_security.Models.Role;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface RoleRepository extends MongoRepository<Role, String>{
}
