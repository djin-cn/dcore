package me.djin.dcore.mq.kafka;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.djin.dcore.exception.ApplicationException;
import me.djin.dcore.mq.FutureCallback;
import me.djin.dcore.mq.Message;
import me.djin.dcore.mq.Producer;

/**
 * @author djin Kafka消息生产者
 */
public abstract class AbstractKafkaProducer implements Producer {
	private static final Logger LOGGER = LoggerFactory.getLogger(AbstractKafkaProducer.class);

	/**
	 * (non-Javadoc)
	 * 
	 * @see me.djin.dcore.mq.Producer#send(java.lang.String, java.lang.String)
	 */
	@Override
	public void send(String topic, String message) {
		send(topic, message, new FutureCallback() {
			@Override
			public void onFailure(Message message, Throwable ex) {
				throw new ApplicationException(new Exception(ex), message);
			}

			@Override
			public void onSuccess(Message message) {
				LOGGER.debug(String.format("topic:%s; message:%s; 发送成功!", topic, message));
			}
		});
	}
}