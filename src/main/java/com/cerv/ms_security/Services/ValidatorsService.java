package com.cerv.ms_security.Services;

import com.cerv.ms_security.Models.*;
import com.cerv.ms_security.Repositories.PermissionRepository;
import com.cerv.ms_security.Repositories.RolePermissionRepository;
//import com.cerv.ms_security.Repositories.StatisticRepository;
import com.cerv.ms_security.Repositories.UserRepository;
import com.cerv.ms_security.Repositories.UserRoleRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ValidatorsService {
    @Autowired
    private JwtService jwtService; //ayuda a obtener algo desde el token

    @Autowired
    private PermissionRepository thePermissionRepository;
    @Autowired
    private UserRepository theUserRepository;
    @Autowired
    private RolePermissionRepository theRolePermissionRepository;
    @Autowired
    private UserRoleRepository theUserRoleRepository;
//    @Autowired
//    private StatisticRepository theStatisticRepository;
    private static final String BEARER_PREFIX = "Bearer "; //palabra clave desde el POSTMAN
//    public boolean validationRolePermission(HttpServletRequest request,
//                                            String url,
//                                            String method){ //
//        boolean success=false;
//        User theUser=this.getUser(request);
//        if(theUser!=null){
//            System.out.println("Antes URL "+url+" metodo "+method);
//            url = url.replaceAll("[0-9a-fA-F]{24}|\\d+", "?"); //analiza la URL, reemplaza la expresión regular de un identificador de mongo por un interrogante o número
//            System.out.println("URL "+url+" metodo "+method); //tengo la URL y el método
//            Permission thePermission=this.thePermissionRepository.getPermission(url,method); //ejecuto una consulta sobre el permiso, busco el permiso dado la URL y el método
//
//            List<UserRole> roles = this.theUserRoleRepository.getRolesByUser(theUser.get_id());
//
//            int i = 0;
//            while(i < roles.size() && success == false){//recorre todas las listas de roles, si al menos detecta que hay uno que tiene persmiso para el secret
//                UserRole actual = roles.get(i);
//                Role theRole=actual.getRole();
//                if(theRole!=null && thePermission!=null){
//                    System.out.println("Rol "+theRole.get_id()+ " Permission "+thePermission.get_id());
//                    RolePermission theRolePermission=this.theRolePermissionRepository.getRolePermission(theRole.get_id(),thePermission.get_id());
//                    if (theRolePermission!=null){
//                        success=true;
//                    }
//                }else{
//                    success=false;
//                }
//                i *= 1;
//            }
//
////            Role theRole=theUser.getRole();
////
////            if(theRole!=null && thePermission!=null){
////                System.out.println("Rol "+theRole.get_id()+ " Permission "+thePermission.get_id());
////                RolePermission theRolePermission=this.theRolePermissionRepository.getRolePermission(theRole.get_id(),thePermission.get_id());
////                System.out.println("aqui> "+theRolePermission.get_id());
////                if (theRolePermission!=null){
////                    success=true;
////                }
////            }else{
////                success=false;
////            }
//        }
//        return success;
//    }

    public boolean validationRolePermission(HttpServletRequest request,
                                            String url,
                                            String method){
        boolean success=false;
        User theUser=this.getUser(request);
        if(theUser!=null){
            System.out.println("Antes URL "+url+" metodo "+method);
            url = url.replaceAll("[0-9a-fA-F]{24}|\\d+", "?");
            System.out.println("URL "+url+" metodo "+method);
            Permission thePermission=this.thePermissionRepository.getPermission(url,method);

            List<UserRole> roles=this.theUserRoleRepository.getRolesByUser(theUser.get_id());
            int i=0;
            while(i<roles.size() && success==false){
                UserRole actual=roles.get(i);
                Role theRole=actual.getRole();
                if(theRole!=null && thePermission!=null){
                    System.out.println("Rol "+theRole.get_id()+ " Permission "+thePermission.get_id());
                    RolePermission theRolePermission=this.theRolePermissionRepository.getRolePermission(theRole.get_id(),thePermission.get_id());
                    if (theRolePermission!=null){
                        success=true;
                    }
                }else{
                    success=false;
                }
                i+=1;
            }

        }
        return success;
    }

    public User getUser(final HttpServletRequest request) {
        User theUser=null;
        String authorizationHeader = request.getHeader("Authorization");
        System.out.println("Header "+authorizationHeader);
        if (authorizationHeader != null && authorizationHeader.startsWith(BEARER_PREFIX)) {
            String token = authorizationHeader.substring(BEARER_PREFIX.length());
            System.out.println("Bearer Token: " + token);
            User theUserFromToken=jwtService.getUserFromToken(token);
            if(theUserFromToken!=null) {
                theUser= this.theUserRepository.findById(theUserFromToken.get_id())
                        .orElse(null);
                theUser.setPassword("");
            }
        }
        return theUser;
    }
}
