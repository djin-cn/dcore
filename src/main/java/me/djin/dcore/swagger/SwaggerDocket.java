/**
 * 
 */
package me.djin.dcore.swagger;

import java.util.ArrayList;
import java.util.List;

import io.swagger.annotations.Api;
import me.djin.dcore.frame.model.CurrentUser;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Parameter;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * @author djin
 * swagger配置工具类类，简化swagger使用
 */
public class SwaggerDocket {
	private ApiInfo apiInfo(String title, String description, String termsOfServiceUrl, String version) {
        return new ApiInfoBuilder()
                .title(title)
                .description(description)
                .termsOfServiceUrl(termsOfServiceUrl)
                .version(version)
                .build();
	}
	/**
	 * 全局参数
	 * @return
	 */
	private List<Parameter> globalParameter(){
		List<Parameter> list = new ArrayList<>();
		ParameterBuilder builder = new ParameterBuilder();
		Parameter param = builder.name(CurrentUser.TOKEN_HEADER).description("用户令牌")
		.modelRef(new ModelRef("String")).parameterType("header")
		.required(false).build();
		list.add(param);
		return list;
	}
	public Docket createDocket(String title, String version) {
		return createDocket(title, null, null, version);
	}
	public Docket createDocket(String title, String description, String version) {
		return createDocket(title, description, null, version);
	}
	public Docket createDocket(String title, String description, String termsOfServiceUrl, String version) {
		return new Docket(DocumentationType.SWAGGER_2)
				.useDefaultResponseMessages(false)
                .apiInfo(apiInfo(title, description, termsOfServiceUrl, version))
//                .globalOperationParameters(globalParameter())
                .select()
                .apis(RequestHandlerSelectors.withClassAnnotation(Api.class))
                .paths(PathSelectors.any())
                .build();
	}
}
