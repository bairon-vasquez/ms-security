package com.cerv.ms_security.Interceptors;

import com.cerv.ms_security.Services.ValidatorsService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

@Component
public class SecurityInterceptor implements HandlerInterceptor { //permite configurar el comportamiento del securityinterceptor(policia) modificar algunos comportamientos
    @Autowired
    private ValidatorsService validatorService; //comportamiento del policia
    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) //antes de que entre a alguna ruta(controlador) coloco el interceptor(policia)
            throws Exception { //try cath para una función
        boolean success=this.validatorService.validationRolePermission(request,request.getRequestURI(),request.getMethod()); //entra la petición luego accede a la URl para luego el método para decir si me deja o no pasar
        return success; //dice si entra o no entra, si es verdadero o falso
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           ModelAndView modelAndView) throws Exception { //el que entra mira que es lo que esta haciendo, analisa los comportamientos del que ingresa
        // Lógica a ejecutar después de que se haya manejado la solicitud por el controlador
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
                                Exception ex) throws Exception { //
        // Lógica a ejecutar después de completar la solicitud, incluso después de la renderización de la vista
    }
}
