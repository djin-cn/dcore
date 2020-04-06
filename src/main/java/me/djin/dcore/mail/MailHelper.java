/**
 * 
 */
package me.djin.dcore.mail;

import java.io.File;
import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.FileSystemResource;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessageHelper;

import me.djin.dcore.exception.ApplicationException;

/**
 * @author djin 邮件发送帮助类，提供邮件发送默认方式
 */
public class MailHelper {
	private static final Logger LOGGER = LoggerFactory.getLogger(MailHelper.class);
	private JavaMailSenderImpl sender = null;
	public MailHelper(SmtpModel smtp) {
		sender = new JavaMailSenderImpl();
		sender.setHost(smtp.getHost());
		sender.setPort(smtp.getPort());
		sender.setUsername(smtp.getUsername());
		sender.setPassword(smtp.getPassword());
		sender.setDefaultEncoding(smtp.getEncoding());
		
		Properties props = new Properties();
		//开启认证
		props.setProperty("mail.smtp.auth", String.valueOf(smtp.isAuth()));
//		props.setProperty("mail.smtp.timeout", "1000");//设置链接超时
		//设置端口
		props.setProperty("mail.smtp.port", String.valueOf(smtp.getPort()));
		props.setProperty("mail.smtp.starttls.enable", String.valueOf(smtp.isTlsEnable()));
		props.setProperty("mail.smtp.starttls.required", String.valueOf(smtp.isTlsRequired()));
		//设置ssl端口
		props.setProperty("mail.smtp.socketFactory.port", String.valueOf(smtp.getPort()));
		props.setProperty("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
		sender.setJavaMailProperties(props);
		LOGGER.trace("初始化MailHelper完成");
	}

	/**
	 * 发送邮件
	 * @param message
	 * @return
	 */
	public boolean send(MailMessage message) {
		if(message.getFrom() == null || message.getFrom().isEmpty()) {
			message.setFrom(sender.getUsername());
		}
		
		//简单邮件
		if (!message.isHtml() && message.getAttachment().isEmpty() && message.getResources().isEmpty()) {
			SimpleMailMessage mailMessage = new SimpleMailMessage();
			mailMessage.setFrom(message.getFrom());
			mailMessage.setTo(ArrayUtils.toStringArray(message.getTo().toArray()));
			mailMessage.setSubject(message.getSubject());
			mailMessage.setText(message.getContent());
			try {
				LOGGER.trace("正在发送SimpleMailMessage");
				this.sender.send(mailMessage);
				LOGGER.trace("SimpleMailMessage发送完成");
			} catch (MailException e) {
				throw new ApplicationException(e, message);
			}
		} else {//Html邮件、包含图片或者附件的邮件
			MimeMessage mimeMessage = sender.createMimeMessage();
			MimeMessageHelper helper = null;
			try {
				helper = new MimeMessageHelper(mimeMessage, true);
				helper.setFrom(message.getFrom());
				helper.setTo(ArrayUtils.toStringArray(message.getTo().toArray()));
				helper.setSubject(message.getSubject());
				helper.setText(message.getContent(), message.isHtml());
				
				//添加静态资源
				if(!message.getResources().isEmpty()) {
					Iterator<Entry<String, String>> it = message.getResources().entrySet().iterator();
					while(it.hasNext()) {
						Entry<String, String> kv = it.next();
						FileSystemResource resource = new FileSystemResource(new File(kv.getValue()));
						helper.addInline(kv.getKey(), resource);
					}
				}
				
				//添加附件
				if(!message.getAttachment().isEmpty()) {
					for (String filepath : message.getAttachment()) {
						FileSystemResource file = new FileSystemResource(new File(filepath));
						helper.addAttachment(file.getFilename(), file);
					}
				}
				LOGGER.trace("正在发送MimeMessage");
				this.sender.send(mimeMessage);
				LOGGER.trace("MimeMessage发送完成");
			} catch (MessagingException e) {
				LOGGER.error("MimeMessage发送失败", e);
				new ApplicationException(e, message);
				return false;
			} catch (MailException e) {
				LOGGER.error("MimeMessage发送失败", e);
				new ApplicationException(e, message);
				return false;
			}
		}
		return true;
	}
}