package me.djin.dcore.frame.model;

import java.util.ArrayList;
import java.util.List;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotNull;
import javax.validation.constraints.Pattern;

import io.swagger.annotations.ApiModelProperty;

/**
 * ID模型，一般用于删除操作
 * @author djin
 *
 */
public class IdListModel {
	@ApiModelProperty(value="ID", required=true)
	@NotNull
	private List<@Pattern(regexp="^\\d+$") @NotBlank String> id;

	public List<String> getId() {
		return id;
	}

	public void setId(List<String> id) {
		this.id = id;
	}
	
	/**
	 * 将字符串形式的ID转换为Long类型
	 * @return
	 */
	public List<Long> toLong(){
		if(getId() == null) {
			return null;
		}
		List<Long> longList = new ArrayList<>();
		getId().forEach((item)->{
			longList.add(Long.valueOf(item));
		});
		return longList;
	}
}