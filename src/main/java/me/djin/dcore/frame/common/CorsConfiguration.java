/**
 * 
 */
package me.djin.dcore.frame.common;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/**
 * @author djin 
 * 
 * 跨域访问设置
 * 
 * 通过dcore.cors.enable设置是否开启跨域访问, 
 * 
 * 默认不开启, 如果需要开启, 可设置dcore.cors.enable=true(建议设置为true, 实际上只要是非false都会当成true处理,包括空字符串或者0)
 */
@Component
@ConditionalOnProperty("dcore.cors.enable")
public class CorsConfiguration {
	@Bean
	public WebMvcConfigurer corsConfigurer() {
		System.out.println("dcore.cors.enable");
		return new WebMvcConfigurer() {
			@Override
			public void addCorsMappings(CorsRegistry registry) {
				// 添加映射路径
				registry.addMapping("/**")
						// 放行哪些原始域
						.allowedOrigins("*")
						// 是否发送Cookie信息
						.allowCredentials(true)
						// 放行哪些请求方式
						.allowedMethods("*")
						// 放行哪些头部信息
						.allowedHeaders("*");
			}
		};
	}
}
