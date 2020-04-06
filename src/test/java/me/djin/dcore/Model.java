package me.djin.dcore;

import java.util.Date;
import java.util.List;

/**
 * 测试实体
 * @author djin
 *
 */
public class Model {
	private Long id;
	private Date updateTime;
	private String account;
	private List<String> roleList;
	public Long getId() {
		return id;
	}
	public void setId(Long id) {
		this.id = id;
	}
	public Date getUpdateTime() {
		return updateTime;
	}
	public void setUpdateTime(Date updateTime) {
		this.updateTime = updateTime;
	}
	public String getAccount() {
		return account;
	}
	public void setAccount(String account) {
		this.account = account;
	}
	public List<String> getRoleList() {
		return roleList;
	}
	public void setRoleList(List<String> roleList) {
		this.roleList = roleList;
	}
}
