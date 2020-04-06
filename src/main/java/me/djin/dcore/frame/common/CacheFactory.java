/**
 * 
 */
package me.djin.dcore.frame.common;

import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.Jackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.stereotype.Component;

import me.djin.dcore.redis.RedisCacheable;

/**
 * @author djin
 * 缓存工厂
 */
@Component
public class CacheFactory {
	/**
	 * RedisTemplate实例
	 * 
	 * 注:
	 * 优化代码时, 如果直接将此方法移到cacheableInstance方法实现, 运行时会提示NPE错误, 原因待查.
	 * @param connectionFactory
	 * @return
	 */
	@Bean(name = "redisTemplate")
	public RedisTemplate<String,Object> redisTemplate(RedisConnectionFactory connectionFactory) {
		RedisTemplate<String, Object> template = new RedisTemplate<>();
		Jackson2JsonRedisSerializer<Object> json = new Jackson2JsonRedisSerializer<>(Object.class);
        // 配置连接工厂
        template.setConnectionFactory(connectionFactory);
        template.setKeySerializer(new StringRedisSerializer());
        template.setValueSerializer(new StringRedisSerializer());
		template.setHashKeySerializer(new StringRedisSerializer());
		template.setHashValueSerializer(json);
		
        return template;
	}
	
	/**
	 * RedisCacheable 实例化
	 * @param redisTemplate
	 * @return
	 */
	@Bean
	public RedisCacheable createRedisCacheable(RedisTemplate<String,Object> redisTemplate) {
		return new RedisCacheable(redisTemplate);
	}
}
