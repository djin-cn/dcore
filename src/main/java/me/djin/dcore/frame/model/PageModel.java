package me.djin.dcore.frame.model;

import java.util.ArrayList;
import java.util.List;

import me.djin.dcore.util.bean.BeanUtils;

/**
 * 分页模型
 * 
 * @author djin
 *
 */
public class PageModel<T> {
	private List<T> list;
	private long total;

	/**
	 * 分页数据
	 * 
	 * @return
	 */
	public List<T> getList() {
		return list;
	}

	/**
	 * 分页数据
	 * 
	 * @param list
	 */
	public void setList(List<T> list) {
		this.list = list;
	}

	/**
	 * 数据总数
	 * 
	 * @return
	 */
	public long getTotal() {
		return total;
	}

	/**
	 * 数据总数
	 * 
	 * @param total
	 */
	public void setTotal(long total) {
		this.total = total;
	}
	
	/**
	 * 将T的分页对象转换为M的分页对象，一般用于转换为M对象
	 * @param clazz
	 * @return
	 */
	public <M> PageModel<M> convert(Class<M> clazz) {
		PageModel<M> page = new PageModel<M>();
		page.setTotal(this.total);
		
		if(this.getList() == null) {
			return page;
		}
		List<M> list = new ArrayList<>(this.getList().size());
		page.setList(list);
		for (T t : this.getList()) {
			M m = BeanUtils.copy(t, clazz);
			list.add(m);
		}
		return page;
	}
}