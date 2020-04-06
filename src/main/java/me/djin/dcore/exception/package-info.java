/**
 * @author djin
 * 异常包
 * Finished time: 201810022324<br/>
 * Usage: <br/>
 * 首先，在classpath目录的error_message.properties文件定义错误信息，错误信息格式为一个错误码对应一个消息<br/>
 * 然后在抛出异常的时候通过错误码抛出异常，同时抛出异常时的上下文数据，为后面的调试提供分析依据。<br/>
 * error_message.properties eg:
 * 10000:您的卡号%s欠款%f元 
 * 
 * 调用方式
 * ApplicationException ex = new ApplicationException(10000, null, "6001 xxxx", 1000);
 * throw ex;
 * 
 * 输出:
 * 您的卡号6001 xxxx欠款1000元
 */
package me.djin.dcore.exception;