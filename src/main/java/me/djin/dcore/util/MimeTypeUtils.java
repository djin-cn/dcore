/**
 * 
 */
package me.djin.dcore.util;

/**
 * @author djin RFC 2045标准的MIME类型
 */
public class MimeTypeUtils {
	public enum Type {
		// 纯文本
		TEXT_PLAIN("text/plain"),
		// HTML文档
		TEXT_HTML("text/html"),
		// XHTML文档
		APPLICATION_XHTML_XML("application/xhtml+xml"),
		APPLICATION_JSON("application/json"),
		// GIF图像
		IMAGE_GIF("image/gif"),
		// JPEG图像
		IMAGE_JPEG("image/jpeg"),
		// PNG图像
		IMAGE_PNG("image/png"),
		// MPEG动画
		VIDEO_MPEG("video/mpeg"),
		// 任意的二进制数据
		APPLICATION_OCTET_STREAM("application/octet-stream"),
		// PDF文档
		APPLICATION_PDF("application/pdf"),
		// Microsoft Word文件
		APPLICATION_MSWORD("application/msword"),
		// wap1.0+。未知？？？
		APPLICATION_VND_WAP_XHTML_XML("application/vnd.wap.xhtml+xml"),
		// RFC 822形式。未知？？？
		MESSAGE_RFC822("message/rfc822"),
		// HTML邮件的HTML形式和纯文本形式，相同内容使用不同形式表示。未知？？
		MUTIPART_ALTERNATIVE("multipart/alternative"),
		// 使用HTTP的POST方法提交的表单
		APPLICATION_X_WWW_FORM_URLENCODED("application/x-www-form-urlencoded"),
		// 同上，但主要用于表单提交时伴随文件上传的场合
		MULTIPART_FORM_DATA("multipart/form-data");

		private String value;

		private Type(String value) {
			this.value = value;
		}

		@Override
		public String toString() {
			return this.value;
		}
	}

	/**
	 * 根据文件解析MIME
	 * @param fileName
	 * @return
	 */
	public static Type parse(String fileName) {
		String[] partions = fileName.split("\\.");
		String ext = partions[partions.length - 1].toLowerCase();
		switch (ext) {
		case "doc":
		case "docx":
			return Type.APPLICATION_MSWORD;
		case "pdf":
			return Type.APPLICATION_PDF;
		case "jpeg":
		case "jpg":
			return Type.IMAGE_JPEG;
		case "gif":
			return Type.IMAGE_GIF;
		case "png":
			return Type.IMAGE_PNG;
		case "htm":
		case "html":
			return Type.TEXT_HTML;
		case "mpg":
		case "mpeg":
			return Type.VIDEO_MPEG;
		case "txt":
			return Type.TEXT_PLAIN;
		default:
			return Type.APPLICATION_OCTET_STREAM;
		}
	}
	
	public static void main(String[] args) {
		Type type = parse("abc.docx");
		System.out.println(type);
	}
}
