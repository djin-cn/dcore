package me.djin.dcore.frame.model;

import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.serializer.ToStringSerializer;

/**
 * 当前用户
 * @author djin
 *
 */
public class CurrentUser {
	public static final String TOKEN_HEADER = "Authorization";
	@JSONField(serializeUsing=ToStringSerializer.class)
	private Long userid;
	private String username;
	private String name;
	private Integer gender;
	/**
	 * 用户系统角色
	 */
	private Integer systemRole;

	/**
	 * 获取用户ID
	 * @return
	 */
	public Long getUserid() {
		return userid;
	}

	/**
	 * 获取登录名
	 * @return
	 */
	public String getUsername() {
		return username;
	}

	/**
	 * 获取用户姓名
	 * @return
	 */
	public String getName() {
		return name;
	}

	/**
	 * 获取用户性别
	 * @return
	 */
	public Integer getGender() {
		return gender;
	}

	/**
	 * 获取系统角色
	 * @return
	 */
	public Integer getSystemRole() {
		return systemRole;
	}

	/**
	 * 设置用户ID
	 * @param userid
	 */
	public void setUserid(Long userid) {
		this.userid = userid;
	}

	/**
	 * 设置登录名
	 * @param username
	 */
	public void setUsername(String username) {
		this.username = username;
	}

	/**
	 * 设置姓名
	 * @param name
	 */
	public void setName(String name) {
		this.name = name;
	}

	/**
	 * 设置用户性别
	 * @param gender
	 */
	public void setGender(Integer gender) {
		this.gender = gender;
	}

	/**
	 * 设置用户系统角色
	 * @param systemRole
	 */
	public void setSystemRole(Integer systemRole) {
		this.systemRole = systemRole;
	}
	
	@Override
	public String toString() {
		return JSONObject.toJSONString(this);
	}
}
