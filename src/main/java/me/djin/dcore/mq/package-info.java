/**
 * 
 */
/**
 * @author djin
 * 异步消息推送，计划将支持ActiveMQ、RabbitMQ、Kafka，优先支持Kafka(此版本已实现)<br />
 * IProducer：消息生产者接口，主要用于发送消息及根据消息发送状态做对应处理
 * IConsumer：消息消费者接口，此接口主要用于规范，没有任何接口方法，实际上可不实现此接口。比如Kafka的消费主要是通过@KafkaListener注解指定，是否实现此接口并不影响实际消费
 */
package me.djin.dcore.mq;