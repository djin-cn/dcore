/**
 * 
 */
package me.djin.dcore.frame.common;

import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import me.djin.dcore.aspect.RequestAspect;

/**
 * @author djin
 * Aspect实例化
 */
@Component
public class AspectBean {
	@Bean
	public RequestAspect createRequestAspect() {
		return new RequestAspect();
	}
}
