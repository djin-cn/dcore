package me.djin.dcore.mybatis;

import java.sql.CallableStatement;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.Map;

import org.apache.ibatis.type.BaseTypeHandler;
import org.apache.ibatis.type.JdbcType;
import org.apache.ibatis.type.MappedTypes;
import org.postgresql.util.PGobject;

import com.alibaba.fastjson.JSON;

/**
 * postgresql数据库json类型字段处理
 * @author djin
 *
 */
@MappedTypes({Map.class, Collection.class})
public class PgsqlJsonTypeHandler extends BaseTypeHandler<Object> {
	@Override
	public void setNonNullParameter(PreparedStatement ps, int i, Object parameter, JdbcType jdbcType)
			throws SQLException {
		PGobject jsonObject = new PGobject();
		jsonObject.setType("json");
		jsonObject.setValue(JSON.toJSONString(parameter));
		 ps.setObject(i, jsonObject);
	}

	@Override
	public Object getNullableResult(ResultSet rs, String columnName) throws SQLException {
		return JSON.parse(rs.getString(columnName));
	}

	@Override
	public Object getNullableResult(ResultSet rs, int columnIndex) throws SQLException {
		return JSON.parse(rs.getString(columnIndex));
	}

	@Override
	public Object getNullableResult(CallableStatement cs, int columnIndex) throws SQLException {
		return JSON.parse(cs.getString(columnIndex));
	}
}