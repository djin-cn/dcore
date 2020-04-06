/**
 * 
 */
package me.djin.dcore.frame.mq;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.KafkaTemplate;

/**
 * @author djin
 *
 *         Kafka自动配置类
 */
@Configuration
@ConditionalOnClass(KafkaTemplate.class)
public class KafkaAutoConfiguration {
	@Autowired
	private KafkaTemplate<Integer, String> kafkaTemplate;

	/**
	 * kafka信息发送模板
	 * @return
	 */
	public KafkaTemplate<Integer, String> getKafkaTemplate() {
		return kafkaTemplate;
	}
}
