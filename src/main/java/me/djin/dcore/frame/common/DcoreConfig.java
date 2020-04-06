package me.djin.dcore.frame.common;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/**
 * 框架初始化配置，为正确配置可能导致某些功能不能正常使用甚至系统无法运行
 * @author djin
 *
 */
@Configuration
public class DcoreConfig {
	@Value("${dcore.mq:thread}")
	private String mq;

	/**
	 * MQ厂商，默认thread
	 * @return
	 */
	public String getMq() {
		return mq;
	}

	/**
	 * MQ厂商
	 * @param mq
	 */
	public void setMq(String mq) {
		this.mq = mq;
	}
}