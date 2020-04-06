package me.djin.dcore.mq.thread;

import me.djin.dcore.core.FactoryContainer;
import me.djin.dcore.mq.Consumer;
import me.djin.dcore.mq.FutureCallback;
import me.djin.dcore.mq.Message;
import me.djin.dcore.mq.MqAbstractFactory;
import me.djin.dcore.mq.Producer;

/**
 * 线程消息生产者
 * @author djin
 *
 */
public class ThreadProducer implements Producer {
	@Override
	public void send(String topic, String message) {
		send(topic, message, new FutureCallback() {

			@Override
			public void onFailure(Message message, Throwable ex) {
			}

			@Override
			public void onSuccess(Message message) {
			}
		});
	}

	@Override
	public void send(String topic, String message, FutureCallback callback) {
		MqAbstractFactory factory = FactoryContainer.getBeanFactory(MqAbstractFactory.class);
		Consumer consumer = factory.createConsumer(topic);
		if (consumer == null) {
			throw new NullPointerException("undefined consumer for topic:" + topic);
		}
		if (callback == null) {
			throw new NullPointerException("undefined callback for topic:" + topic);
		}
		ThreadMessagePool.getInstance().submit(topic, message, callback, consumer);
	}
}
