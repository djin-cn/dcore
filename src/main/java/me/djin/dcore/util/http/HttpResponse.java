package me.djin.dcore.util.http;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import com.alibaba.fastjson.JSON;

import okhttp3.Response;

/**
 * Http响应
 * @author djin
 *
 */
public class HttpResponse {
	private Response response = null;
	
	public HttpResponse(Response response) {
		this.response = response;
	}
	
	/**
	 * 获取Http响应，Response操作完成后需要将Response关闭，可调用Response.close()方法。
	 * @return
	 */
	public Response getResponse() {
		return response;
	}
	
	/**
	 * 获取内容
	 * @return
	 * @throws IOException
	 */
	public String getString() throws IOException {
		String content = null;
		try {
			content = response.body().string();
		} catch (IOException e) {
			throw e;
		}finally {
			response.close();			
		}
		return content;
	}
	
	/**
	 * 获取JSON数据。采用fastjson解析的数据，对象类型一般为JSONObject或者JSONArray
	 * @return
	 * @throws IOException
	 */
	public Object getJson() throws IOException{
		String content = getString();
		return JSON.parse(content);
	}
	
	/**
	 * 获取内容并保存到文件
	 * @param filePath 保存地址
	 * @throws IOException
	 */
	public File getFile(String filePath) throws IOException {
		File file = new File(filePath);
		if(!file.exists()) {
			if(!file.mkdirs()) {
				throw new IOException("can not create directory:"+filePath);
			}
		}
		byte[] bytes=new byte[1024];
		int count = 0;
		InputStream inStream = null;
		FileOutputStream outStream = null;
		try {
			inStream = response.body().byteStream();
			outStream = new FileOutputStream(filePath);
			while((count = inStream.read(bytes)) != -1) {
				outStream.write(bytes, 0, count);
				outStream.flush();
			}
			inStream.close();
			outStream.close();
		}catch(IOException e) {
			throw e;
		}finally {
			if(inStream != null) {
				inStream.close();
			}
			if(outStream != null) {
				outStream.close();
			}
			response.close();
		}
		return file;
	}
}