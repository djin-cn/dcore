/**
 * 
 */
package me.djin.dcore.mail;

import java.util.ArrayList;
import java.util.HashMap;

/**
 * @author djin 邮件信息
 */
public class MailMessage {
	private String from;
	private ArrayList<String> to = new ArrayList<String>();
	private String subject;
	private String content;
	private boolean html = true;
	private HashMap<String, String> resources = new HashMap<String, String>();
	private ArrayList<String> attachment = new ArrayList<String>();

	/**
	 * 发送者，可以为空,建议与SMTP用户一致，否则某些邮箱可能会发送失败，如163邮箱，默认为smtp用户
	 * 
	 * @return
	 */
	public String getFrom() {
		return from;
	}

	/**
	 * 发送者，可以为空,建议与SMTP用户一致，否则某些邮箱可能会发送失败，如163邮箱，默认为smtp用户
	 * 
	 * @param from
	 */
	public void setFrom(String from) {
		this.from = from;
	}

	/**
	 * 接收者
	 * 
	 * @return
	 */
	public ArrayList<String> getTo() {
		return to;
	}

	/**
	 * 邮件主题，不能为空
	 * 
	 * @return
	 */
	public String getSubject() {
		return subject;
	}

	/**
	 * 邮件主题，不能为空
	 * 
	 * @param subject
	 */
	public void setSubject(String subject) {
		this.subject = subject;
	}

	/**
	 * 邮件内容，不能为空
	 * 
	 * @return
	 */
	public String getContent() {
		return content;
	}

	/**
	 * 邮件内容，不能为空
	 * 
	 * @param text
	 */
	public void setContent(String text) {
		this.content = text;
	}

	/**
	 * 邮件内容是否Html格式，默认为是
	 * 
	 * @return
	 */
	public boolean isHtml() {
		return html;
	}

	/**
	 * 邮件内容是否Html格式，默认为是
	 * 
	 * @param html
	 */
	public void setHtml(boolean html) {
		this.html = html;
	}

	/**
	 * 邮件内容嵌入的静态资源，键为嵌入的资源名称，值为完整资源路径
	 * 
	 * @return
	 */
	public HashMap<String, String> getResources() {
		return resources;
	}

	/**
	 * 邮件附件路径
	 * 
	 * @return
	 */
	public ArrayList<String> getAttachment() {
		return attachment;
	}
}