package me.djin.dcore.mq;

/**
 * @author djin
 * 消息消费者，处理消息.类名建议按照消息主题+Consumer方式命名，如注册用户消息:RegisterUserConsumer
 */
public interface Consumer {
	/**
	 * 消息处理
	 * @param message 要处理的消息
	 */
	void process(String message);
}