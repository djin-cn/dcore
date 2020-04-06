package me.djin.dcore.frame.common;

import java.util.List;

import com.github.pagehelper.PageHelper;

import me.djin.dcore.frame.model.PageModel;

/**
 * @author djin 基础服务接口，提供常规增删改查
 * @param <T>
 *            实体类
 */
public interface CurdService<T> {
	/**
	 * 添加数据
	 * 
	 * @param t
	 *            PO实例
	 * @return
	 */
	default long add(T t) {
		if (t == null) {
			return 0;
		}
		CurdBaseDao<T> dao = ServiceHelper.getInstance(t);
		return dao.insert(t);
	}

	/**
	 * 批量添加数据
	 * 
	 * @param list
	 * @return
	 */
	default long add(List<T> list) {
		if (list == null || list.isEmpty()) {
			return 0;
		}
		CurdDao<T> dao = (CurdDao<T>) ServiceHelper.getInstance(list.get(0));
		return dao.insertList(list);
	}

	/**
	 * 添加数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param model
	 *            VO实例
	 * @return
	 */
	/*
	 * default long add(Class<T> clazz, Object model) { T t; try { t =
	 * clazz.newInstance(); } catch (InstantiationException | IllegalAccessException
	 * e) { throw new ApplicationException(e, clazz); } try {
	 * BeanUtils.copyProperties(t, model); } catch (IllegalAccessException |
	 * InvocationTargetException e) { throw new ApplicationException(e, model); }
	 * return add(t); }
	 */

	/**
	 * 根据主键修改数据
	 * 
	 * @param t
	 *            PO实例
	 * @return
	 */
	default long update(T t) {
		if (t == null) {
			return 0;
		}
		CurdBaseDao<T> dao = ServiceHelper.getInstance(t);
		return dao.updateByPrimaryKeySelective(t);
	}

	/**
	 * 根据主键修改数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param model
	 *            VO实例
	 * @return
	 */
	/*
	 * default long update(Class<T> clazz, Object model) { T t; try { t =
	 * clazz.newInstance(); } catch (InstantiationException | IllegalAccessException
	 * e) { throw new ApplicationException(e, clazz); } try {
	 * BeanUtils.copyProperties(t, model); } catch (IllegalAccessException |
	 * InvocationTargetException e) { throw new ApplicationException(e, model); }
	 * return update(t); }
	 */

	/**
	 * 删除数据
	 * 
	 * @param t
	 *            PO实例，以实例中非NULL的属性为删除条件
	 * @return
	 */
	default long delete(T t) {
		if (t == null) {
			return 0;
		}
		CurdBaseDao<T> dao = ServiceHelper.getInstance(t);
		return dao.delete(t);
	}

	/**
	 * 根据主键ID删除数据
	 * 
	 * @param clazz
	 * @param id
	 * @return
	 */
	default long delete(Class<T> clazz, long id) {
		CurdBaseDao<T> dao = ServiceHelper.getInstance(clazz);
		return dao.deleteByPrimaryKey(id);
	}

	/**
	 * 根据主键ID删除数据
	 * 
	 * @param clazz
	 * @param idList
	 * @return
	 */
	default long delete(Class<T> clazz, List<Long> idList) {
		if (idList == null || idList.isEmpty()) {
			return 0;
		}
		// 只删除一条数据
		if (idList.size() == 1) {
			return delete(clazz, idList.get(0).longValue());
		}
		CurdDao<T> dao = (CurdDao<T>) ServiceHelper.getInstance(clazz);
		return dao.deleteByIdList(idList);
	}

	/**
	 * 删除数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param model
	 *            VO实例，以实例中非NULL的属性为删除条件
	 * @return
	 */
	/*
	 * default long delete(Class<T> clazz, Object model) { T t; try { t =
	 * clazz.newInstance(); } catch (InstantiationException | IllegalAccessException
	 * e) { throw new ApplicationException(e, clazz); } try {
	 * BeanUtils.copyProperties(t, model); } catch (IllegalAccessException |
	 * InvocationTargetException e) { throw new ApplicationException(e, model); }
	 * return delete(t); }
	 */

	/**
	 * 获取一条数据，一般用来获取主键数据
	 * 
	 * @param t
	 *            PO实例，以实例中非NULL属性为条件获取一条数据，一般以主键为条件
	 * @return
	 */
	default T get(T t) {
		if (t == null) {
			return null;
		}
		CurdBaseDao<T> dao = ServiceHelper.getInstance(t);
		return dao.selectOne(t);
	}

	/**
	 * 根据ID获取数据
	 * 
	 * @param clazz
	 * @param id
	 * @return
	 */
	default T get(Class<T> clazz, long id) {
		CurdBaseDao<T> dao = ServiceHelper.getInstance(clazz);
		return dao.selectByPrimaryKey(id);
	}

	/**
	 * 获取一条数据，一般用来获取主键数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param model
	 *            VO实例，以实例中非NULL属性为条件获取一条数据，一般以主键为条件
	 * @return
	 */
	/*
	 * default T get(Class<T> clazz, Object model) { T t; try { t =
	 * clazz.newInstance(); } catch (InstantiationException | IllegalAccessException
	 * e) { throw new ApplicationException(e, clazz); } try {
	 * BeanUtils.copyProperties(t, model); } catch (IllegalAccessException |
	 * InvocationTargetException e) { throw new ApplicationException(e, model); }
	 * return get(t); }
	 */

	/**
	 * 获取所有数据
	 * 
	 * @param clazz
	 *            PO类
	 * @return
	 */
	default List<T> list(Class<T> clazz) {
		CurdBaseDao<T> dao = ServiceHelper.getInstance(clazz);
		return dao.selectAll();
	}

	/**
	 * 获取符合条件的所有数据
	 * 
	 * @param t
	 *            PO实例，以非NULL属性为条件，不能为NULL，否则获取不到数据
	 * @return
	 */
	default List<T> list(T t) {
		if (t == null) {
			return null;
		}
		CurdBaseDao<T> dao = ServiceHelper.getInstance(t);
		return dao.select(t);
	}

	/**
	 * 获取符合条件的所有数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param model
	 *            VO实例，以非NULL属性为条件，VO实例不能为NULL，否则获取不到数据
	 * @return
	 */
	/*
	 * default List<T> list(Class<T> clazz, Object model) { T t; try { t =
	 * clazz.newInstance(); } catch (InstantiationException | IllegalAccessException
	 * e) { throw new ApplicationException(e, clazz); } try {
	 * BeanUtils.copyProperties(t, model); } catch (IllegalAccessException |
	 * InvocationTargetException e) { throw new ApplicationException(e, model); }
	 * return list(t); }
	 */

	/**
	 * 分页获取所有数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param pageNumber
	 *            页码
	 * @param pageSize
	 *            每页数量
	 * @return
	 */
	default PageModel<T> list(Class<T> clazz, int pageNumber, int pageSize) {
		CurdBaseDao<T> dao = ServiceHelper.getInstance(clazz);
		PageHelper.startPage(pageNumber, pageSize);
		List<T> list = dao.selectAll();
		int count = dao.selectCount(null);
		if (list == null || list.isEmpty()) {
			return new PageModel<>();
		}
		PageModel<T> pageModel = new PageModel<T>();
		pageModel.setList(list);
		pageModel.setTotal(count);
		return pageModel;
	}

	/**
	 * 分页获取符合条件所有数据
	 * 
	 * @param t
	 *            PO实例，以非NULL属性为条件
	 * @param pageNumber
	 *            页码
	 * @param pageSize
	 *            每页数量
	 * @return
	 */
	default PageModel<T> list(T t, int pageNumber, int pageSize) {
		if (t == null) {
			return new PageModel<>();
		}
		CurdBaseDao<T> dao = ServiceHelper.getInstance(t);
		PageHelper.startPage(pageNumber, pageSize);
		List<T> list = dao.select(t);
		int count = dao.selectCount(t);
		if (list == null || list.isEmpty()) {
			return new PageModel<>();
		}
		PageModel<T> pageModel = new PageModel<T>();
		pageModel.setList(list);
		pageModel.setTotal(count);
		return pageModel;
	}

	/**
	 * 分页获取符合条件所有数据
	 * 
	 * @param clazz
	 *            PO类
	 * @param model
	 *            VO实例,以非NULL字段为查询条件
	 * @param pageNumber
	 *            页码
	 * @param pageSize
	 *            每页数量
	 * @return
	 */
	/*
	 * default PageModel<T> list(Class<T> clazz, Object model, int pageNumber, int
	 * pageSize) { T t; try { t = clazz.newInstance(); } catch
	 * (InstantiationException | IllegalAccessException e) { throw new
	 * ApplicationException(e, clazz); } try { BeanUtils.copyProperties(t, model); }
	 * catch (IllegalAccessException | InvocationTargetException e) { throw new
	 * ApplicationException(e, model); } return list(t, pageNumber, pageSize); }
	 */
}