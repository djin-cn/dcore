package me.djin.dcore.frame.model;

import io.swagger.annotations.ApiModelProperty;

/**
 * 关键字查询模型
 * @author djin
 *
 */
public class KeywordQueryModel extends QueryModel {
	@ApiModelProperty(value="关键词")
	private String kw;

	/**
	 * 获取关键词
	 * @return
	 */
	public String getKw() {
		return kw;
	}

	/**
	 * 设置关键词
	 * @param kw
	 */
	public void setKw(String kw) {
		this.kw = kw;
	}
}
