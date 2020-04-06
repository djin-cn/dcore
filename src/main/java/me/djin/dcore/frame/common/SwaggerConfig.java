package me.djin.dcore.frame.common;

import java.util.Arrays;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.google.common.base.Predicate;

import me.djin.dcore.frame.model.CurrentUser;
import me.djin.dcore.swagger.SwaggerDocket;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

/**
 * 
 * @author djin
 *
 */
@EnableSwagger2
@Configuration
@Profile({"dev", "debug"})
public class SwaggerConfig {
 
    /**
     * 创建接口文档
     * @return
     */
    @Bean
    public Docket createRestApiDocument() {
    	SwaggerDocket tool = new SwaggerDocket();
    	return tool.createDocket("接口文档", "1.0")
    			.useDefaultResponseMessages(false)
    			.securitySchemes(securitySchemes())
    			.securityContexts(securityContexts());
    }
    
    private Predicate<String> pathSelector() {
    	return PathSelectors.regex("^/admin/.*$");
    }
    
    private List<ApiKey> securitySchemes(){
    	return Arrays.asList(new ApiKey(CurrentUser.TOKEN_HEADER, CurrentUser.TOKEN_HEADER, "header"));
    }
    
    private List<SecurityContext> securityContexts(){
    	return Arrays.asList(SecurityContext.builder()
    			.securityReferences(securityReferences())
    			.forPaths(pathSelector())
    			.build());
    }
    
    private List<SecurityReference> securityReferences(){
    	AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Arrays.asList(new SecurityReference(CurrentUser.TOKEN_HEADER, authorizationScopes));
    }
}
