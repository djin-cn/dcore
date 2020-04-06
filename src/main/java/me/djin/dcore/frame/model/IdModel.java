package me.djin.dcore.frame.model;

import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.swagger.annotations.ApiModelProperty;

/**
 * ID模型，一般用于删除、获取详情等操作
 * @author djin
 *
 */
public class IdModel {
	@ApiModelProperty(value="ID", required=true)
	@NotNull
	@Pattern(regexp="^\\d+$")
	private String id;

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}
}