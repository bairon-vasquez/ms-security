package com.cerv.ms_security.Repositories;

import com.cerv.ms_security.Models.UserRole;
import org.springframework.data.mongodb.repository.MongoRepository;
import org.springframework.data.mongodb.repository.Query;

import java.util.List;

public interface UserRoleRepository extends MongoRepository<UserRole, String> {
    @Query("{'user.$id': ObjectId(?0)}")
    public List<UserRole> getRolesByUser(String userId);

    @Query("{'role.$id': ObjectId(?0)}")
    public List<UserRole> getUsersByRole(String roleId);

    @Query("{ 'user.$id' : ObjectId(?0) }")
    public List<UserRole> getRolesByUserId(String userId);


}
