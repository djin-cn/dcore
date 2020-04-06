/**
 * 
 */
package me.djin.dcore.frame.test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.WebApplicationContext;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alibaba.fastjson.TypeReference;

import me.djin.dcore.frame.model.PageModel;
import me.djin.dcore.frame.model.Response;


/**
 * @author djin 
 * 
 * 测试基类
 * 
 * 所有测试都以事务的方式运行, 运行完成后即回滚, 不会在数据库产生脏数据
 */
@ConditionalOnClass({org.springframework.boot.test.context.SpringBootTest.class
	, org.springframework.test.annotation.Rollback.class
	, org.junit.runner.RunWith.class
	, org.springframework.test.context.junit4.SpringRunner.class
	})
@Transactional(rollbackFor = Exception.class)
@org.springframework.test.annotation.Rollback
@org.junit.runner.RunWith(org.springframework.test.context.junit4.SpringRunner.class)
@org.springframework.boot.test.context.SpringBootTest(webEnvironment = org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT)
public abstract class BaseTest {
	@LocalServerPort
    protected int port;
	/**
     * 性能测试
     */
	@org.junit.Rule
	public org.databene.contiperf.junit.ContiPerfRule contiPerfRule = new org.databene.contiperf.junit.ContiPerfRule();
	/**
	 * 当前测试环境的上下文
	 */
	@Autowired
	private WebApplicationContext webApplicationContext;
	/**
	 * MockMvc对象
	 */
	protected org.springframework.test.web.servlet.MockMvc mockMvc;

	@org.junit.Before
	public void setUp() throws Exception {
		mockMvc = org.springframework.test.web.servlet.setup.MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
	}

	/**
	 * NULL值测试
	 */
	@org.junit.Test
	public abstract void nullTest();

	/**
	 * 空字符串测试, 对于数字类型和日期类型的字段空字符串等效于NULL
	 */
	@org.junit.Test
	public abstract void emptyTest();

	/**
	 * 正例测试, 此用例一定是完全正确的是示例, 所有输入都符合规则, 建议所有参数都有输入值
	 */
	@org.junit.Test
	public abstract void correct();

	/**
	 * 通过MockMvc模拟post请求调用接口, 返回非泛型T对象(即T不是泛型)
	 * @param url 地址, 不需要包含域名/端口/contextPath
	 * @param params 参数
	 * @param returnClazz 返回类型
	 * @return
	 */
	public <T> Response<T> post(String url, Object params, Class<T> returnClazz) {
		String result;
		try {
			result = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(url).contentType(MediaType.APPLICATION_JSON)
							.content(JSON.toJSONString(params)))
					.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
					.andDo(new org.springframework.test.web.servlet.ResultHandler() {
						@Override
						public void handle(org.springframework.test.web.servlet.MvcResult result) throws Exception {
							System.out.println(JSON.toJSONString(params));
						}
					})
					.andDo(org.springframework.test.web.servlet.result.MockMvcResultHandlers.print()).andReturn()
					.getResponse().getContentAsString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		JSONObject json = JSON.parseObject(result);
		T data = null;
		try {
			data = json.getObject("data", returnClazz);
		} catch (Exception e) {
			data = null;
		}
		Response<T> response = new Response<T>(json.getString("status"), data);
		return response;
	}
	
	/**
	 * 通过MockMvc模拟post请求调用接口, 返回PageModel<T>对象, 一般用于获取列表接口
	 * @param url 地址, 不需要包含域名/端口/contextPath
	 * @param params 参数
	 * @param returnClazz 返回类型
	 * @return
	 */
	public <T> Response<PageModel<T>> postByPageResult(String url, Object params, Class<T> returnClazz) {
		String result;
		try {
			result = mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(url).contentType(MediaType.APPLICATION_JSON)
					.content(JSON.toJSONString(params)))
				.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
				.andDo(new org.springframework.test.web.servlet.ResultHandler() {
					@Override
					public void handle(org.springframework.test.web.servlet.MvcResult result) throws Exception {
						System.out.println(JSON.toJSONString(params));
					}
				})
				.andDo(org.springframework.test.web.servlet.result.MockMvcResultHandlers.print()).andReturn()
				.getResponse().getContentAsString();
		} catch (Exception e) {
			throw new RuntimeException(e);
		}
		JSONObject json = JSON.parseObject(result);
		PageModel<T> data = null;
		try {
			data = json.getObject("data", new TypeReference<PageModel<T>>(returnClazz) {
			});
		} catch (Exception e) {
			data = null;
		}
		Response<PageModel<T>> response = new Response<PageModel<T>>(json.getString("status"), data);
		return response;
	}
	
	/**
	 * ne表示NULL和EMPTY
	 * NULL或者EMPTY校验时, 返回的状态码只有两种情况{1:操作成功;2:参数校验失败}, 如果是这两种状态码则表示验证通过, 否则验证失败
	 * @param response
	 * @return
	 */
	public boolean neValid(Response<?> response) {
		return "1".equals(response.getStatus()) || "2".equals(response.getStatus());
	}
	
	/**
	 * 逐一生成NULL属性
	 * @param model 所有属性值必须非NULL且非EMPTY的正常值
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <T> List<T> generateNullProperty(T model){
		List<T> list = new ArrayList<T>();
		Field[] fields = model.getClass().getDeclaredFields();
		for (Field field : fields) {
			T tmp = (T)JSON.parseObject(JSON.toJSONString(model), model.getClass());
			field.setAccessible(true);
			try {
				field.set(tmp, null);
				list.add(tmp);
			} catch (IllegalArgumentException | IllegalAccessException e) {
				System.out.println(e);
			}
		}
		return list;
	}
	
	/**
	 * 逐一生成空字符串属性
	 * @param model 所有属性值必须非NULL且非EMPTY的正常值
	 * @return
	 */
	@SuppressWarnings("unchecked")
	public <T> List<T> generateEmptyProperty(T model){
		List<T> list = new ArrayList<T>();
		Field[] fields = model.getClass().getDeclaredFields();
		for (Field field : fields) {
			T tmp = (T)JSON.parseObject(JSON.toJSONString(model), model.getClass());
			field.setAccessible(true);
			try {
				field.set(tmp, "");
				list.add(tmp);
			} catch (IllegalArgumentException | IllegalAccessException e) {
			}
		}
		return list;
	}
}