package me.djin.dcore;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

import me.djin.dcore.mq.Consumer;

/**
 * 演示kafka消费者
 * 
 * @author djin
 *
 */
@Component
public class KafkaConsumer implements Consumer {

	/**
	 * KafkaListener不会自动启动，实际使用过程中一般不会设autoStartup=false;
	 * @param message
	 */
	@KafkaListener(topics = { "test" }, autoStartup="false")
	@Override
	public void process(String message) {
		System.out.println(this.getClass().getName()+message);
	}
}