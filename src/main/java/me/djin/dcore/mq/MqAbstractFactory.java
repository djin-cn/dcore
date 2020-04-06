package me.djin.dcore.mq;

import me.djin.dcore.core.BeanFactory;

/**
 * 异步消息抽象工厂
 * @author djin
 *
 */
public interface MqAbstractFactory extends BeanFactory {
	/**
	 * 创建消息生产对象
	 * @return
	 */
	Producer createProducer();
	/**
	 * 创建消息消费对象
	 * @param topic 主题
	 * @return
	 */
	Consumer createConsumer(String topic);
}
