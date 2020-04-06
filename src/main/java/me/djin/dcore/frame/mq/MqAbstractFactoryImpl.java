/**
 * 
 */
package me.djin.dcore.frame.mq;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Component;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.util.concurrent.ListenableFutureCallback;

import me.djin.dcore.core.FactoryContainer;
import me.djin.dcore.frame.common.DcoreConfig;
import me.djin.dcore.mq.Consumer;
import me.djin.dcore.mq.FutureCallback;
import me.djin.dcore.mq.Message;
import me.djin.dcore.mq.Message.Status;
import me.djin.dcore.mq.MqAbstractFactory;
import me.djin.dcore.mq.Producer;
import me.djin.dcore.mq.kafka.AbstractKafkaProducer;
import me.djin.dcore.mq.thread.DemoConsumer;
import me.djin.dcore.mq.thread.ThreadMessagePool;
import me.djin.dcore.mq.thread.ThreadProducer;
import me.djin.dcore.util.spring.SpringContextUtil;

/**
 * @author djin MQ工厂实现，通过配置文件的dcore.mq指定MQ提供者。
 */
@Component
public class MqAbstractFactoryImpl implements MqAbstractFactory {
	private static final String DEFAULT_THREAD_MQ = "demo";
	@Autowired
	private DcoreConfig cfg;
	@Autowired(required=false)
	private KafkaAutoConfiguration kafkaConfig;
//	@Autowired(required=false)
//	private KafkaTemplate<Integer, String> kafkaTemplate;
	
	public MqAbstractFactoryImpl() {
		FactoryContainer.addBeanFactory(MqAbstractFactory.class, this);
	}

	/**
	 * 通过配置文件的dcore.mq指定MQ提供者。
	 * 线程MQ只支持单机方式通过多线程创建消息，不支持集群，如需集群支持可采用其他厂商提供的产品，如:kafka, activemq, rabbitmq等。
	 * 如果未指定，默认使用ThreadMQ，如需手动指定为ThreadMQ，则必须配置为thread。其他厂商的可自定义，符合命名规则即可。
	 * 通过此方法创建的MQ实例，必须遵从以下命名规则：dcore.mq配置项+Producer，如配置项指定为active，则Producer必须命名为ActiveProducer。
	 * 
	 * 框架默认提供了两种MQ：ThreadMQ、Kafka。Kafka需要安装服务以提供MQ服务；ThreadMQ不需要，可直接使用。
	 * 
	 * @return
	 */
	@Bean
	@Override
	public Producer createProducer() {
		Producer producer = null;
		String factoryName = cfg.getMq().toLowerCase();
		switch (factoryName) {
		case "kafka":
			producer = new AbstractKafkaProducer() {
				@Override
				public void send(String topic, String message, FutureCallback callback) {
					ListenableFuture<SendResult<Integer, String>> future = kafkaConfig.getKafkaTemplate().send(topic, message);
					future.addCallback(new ListenableFutureCallback<SendResult<Integer, String>>() {
						@Override
						public void onSuccess(SendResult<Integer, String> result) {
							Message message = new Message();
							message.setTopic(result.getProducerRecord().topic());
							message.setMessage(result.getProducerRecord().value());
							message.setStatus(Status.SUCCESS);
							callback.onSuccess(message);
						}

						@Override
						public void onFailure(Throwable ex) {
							callback.onFailure(null, ex);
						}
					});
				}
			};
			break;
		default:
			producer = new ThreadProducer();
			ThreadMessagePool.getInstance();
			break;
		}
		return producer;
	}

	/**
	 * 基本上只有多线程消息才会用到
	 */
	@Override
	public Consumer createConsumer(String topic) {
		Consumer consumer = null;
		String beanId = StringUtils.uncapitalize(topic)+"Consumer";
		try {
			consumer = (Consumer)SpringContextUtil.getBean(beanId);
		}catch(BeansException e) {
			if(topic == DEFAULT_THREAD_MQ) {
				consumer = new DemoConsumer();
			}
		}
		return consumer;
	}

}
