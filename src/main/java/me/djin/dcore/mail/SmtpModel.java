package me.djin.dcore.mail;

import java.io.Serializable;

/**
 * 
 * @author djin
 *
 */
@SuppressWarnings("serial")
public class SmtpModel implements Serializable {
	private String host;
	private int port;
	private String username;
	private String password;
	private String encoding = "UTF-8";
	private boolean auth;
	private boolean tlsEnable;
	private boolean tlsRequired;

	/**
	 * smtp服务器地址
	 * 
	 * @return
	 */
	public String getHost() {
		return host;
	}

	/**
	 * smtp服务器地址
	 * 
	 * @param host
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * smtp服务器端口
	 * 
	 * @return
	 */
	public int getPort() {
		return port;
	}

	/**
	 * smtp服务器端口(一般为25);如果启用了SSL，则采用SSL端口(一般为465);如果启用了TLS，则采用TLS端口(gmail为587);
	 * 
	 * @param port
	 */
	public void setPort(int port) {
		this.port = port;
	}

	/**
	 * smtp用户名称
	 * 
	 * @return
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * smtp用户名称
	 * 
	 * @param username
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * smtp密码
	 * 
	 * @return
	 */
	public String getPassword() {
		return password;
	}

	/**
	 * smtp密码
	 * 
	 * @param password
	 */
	public void setPassword(String password) {
		this.password = password;
	}

	/**
	 * smpt编码
	 * 
	 * @return
	 */
	public String getEncoding() {
		return encoding;
	}

	/**
	 * smpt编码
	 * 
	 * @param encoding
	 */
	public void setEncoding(String encoding) {
		this.encoding = encoding;
	}

	/**
	 * 是否需要身份验证,默认false
	 * 
	 * @return
	 */
	public boolean isAuth() {
		return auth;
	}

	/**
	 * 是否需要身份验证,默认false
	 * 
	 * @param auth
	 */
	public void setAuth(boolean auth) {
		this.auth = auth;
	}

	/**
	 * 是否开启tls,默认false
	 * @return
	 */
	public boolean isTlsEnable() {
		return tlsEnable;
	}

	/**
	 * 是否开启tls,默认false
	 * @param tlsEnable
	 */
	public void setTlsEnable(boolean tlsEnable) {
		this.tlsEnable = tlsEnable;
	}

	/**
	 * 是否需要tls,默认false
	 * @return
	 */
	public boolean isTlsRequired() {
		return tlsRequired;
	}

	/**
	 * 是否需要tls,默认false
	 * @param tlsRequired
	 */
	public void setTlsRequired(boolean tlsRequired) {
		this.tlsRequired = tlsRequired;
	}
}