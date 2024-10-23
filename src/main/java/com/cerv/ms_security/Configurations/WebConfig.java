package com.cerv.ms_security.Configurations;

import com.cerv.ms_security.Interceptors.SecurityInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration//ayudan a determinar comportamientos que se van a tener en el código, configurar el esquema de seguridad, de la clase de interceptores
public class WebConfig implements WebMvcConfigurer { //configura la interfaz, manipulando scripts cuando se ejecuten en determinadas capaz, para levantar el esquema de seguirdad
    @Autowired //inyecta el securityinterceptor
    private SecurityInterceptor securityInterceptor; //El que verifica el token, es un interceptor, como un policia que verifica
    //interfaz contrato de métodos que estoy obligado a seguir
    @Override
    public void addInterceptors(InterceptorRegistry registry) { //registry permite configurar una capa que va a envolver el proyecto


//        registry.addInterceptor(securityInterceptor) //colocar capa de seguridad a todo lo que en la endpoint empieze por api
//                .addPathPatterns("/api/**")
//                .excludePathPatterns("/api/public/**");


    }
}