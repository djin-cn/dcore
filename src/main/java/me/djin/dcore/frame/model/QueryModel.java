package me.djin.dcore.frame.model;

import javax.validation.constraints.Pattern;

import org.apache.commons.lang3.StringUtils;

import io.swagger.annotations.ApiModelProperty;

/**
 * 查询模型
 * @author djin
 *
 */
public class QueryModel {
	@ApiModelProperty(value="排序属性，默认按id排序")
	@Pattern(regexp="^[\\w\\.]+$", message="字符只能为字母或者下划线")
	private String order;
	@ApiModelProperty(value="排序方式，值只能是asc或者desc，默认desc排列")
	@Pattern(regexp="asc|desc", message="只能为asc或者desc")
	private String mode;
	/**
	 * 获取排序属性，如果排序属性为NULL或者空字符，则设置默认排序属性为id;，即必定会有排序属性
	 * @return
	 */
	public String getOrder() {
		if(StringUtils.isBlank(order)) {
			setOrder("id");
		}
		return order;
	}
	/**
	 * 设置排序属性，如果排序属性为NULL或者空字符，则设置默认排序属性为id;，即必定会有排序属性
	 * @return
	 */
	public void setOrder(String order) {
		this.order = order;
	}
	/**
	 * 获取排序方式，如果排序方式为NULL，则设置默认的排序方式为desc，即必定会有排序方式
	 * @return
	 */
	public String getMode() {
		if(null == mode) {
			setMode("desc");
		}
		return mode;
	}
	/**
	 * 设置排序方式，如果排序方式为NULL，则设置默认的排序方式为desc，即必定会有排序方式
	 * @param mode 排序方式，值只能为asc或者desc
	 * @return
	 */
	public void setMode(String mode) {
		/*if(!"desc".equals(mode) && !"asc".equals(mode)) {
			mode = "desc";
		}*/
		this.mode = mode;
	}
	
}
