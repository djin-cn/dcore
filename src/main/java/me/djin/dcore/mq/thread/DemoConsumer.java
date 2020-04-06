package me.djin.dcore.mq.thread;

import me.djin.dcore.mq.Consumer;

/**
 * MQ线程消息DEMO，无实际意义，只用于演示功能
 * @author djin
 *
 */
public class DemoConsumer implements Consumer {

	@Override
	public void process(String message) {
		System.out.println("Demo Consumer");
	}

}
