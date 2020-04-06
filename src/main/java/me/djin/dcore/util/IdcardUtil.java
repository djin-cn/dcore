package me.djin.dcore.util;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.regex.Pattern;

/**
 * 身份证前6位【ABCDEF】为行政区划数字代码（简称数字码）说明（参考《GB/T 2260-2007 中华人民共和国行政区划代码》）：
 * 该数字码的编制原则和结构分析，它采用三层六位层次码结构，按层次分别表示我国各省（自治区，直辖市，特别行政区）、市（地区，自治州，盟）、县（自治县、县级市、旗、自治旗、市辖区、林区、特区）。
 * 数字码码位结构从左至右的含义是： 第一层为AB两位代码表示省、自治区、直辖市、特别行政区；
 * 第二层为CD两位代码表示市、地区、自治州、盟、直辖市所辖市辖区、县汇总码、省（自治区）直辖县级行政区划汇总码，其中：
 * ——01~20、51~70表示市，01、02还用于表示直辖市所辖市辖区、县汇总码； ——21~50表示地区、自治州、盟；
 * ——90表示省（自治区）直辖县级行政区划汇总码。 第三层为EF两位表示县、自治县、县级市、旗、自治旗、市辖区、林区、特区，其中：
 * ——01~20表示市辖区、地区（自治州、盟）辖县级市、市辖特区以及省（自治区）直辖县级行政区划中的县级市，01通常表示辖区汇总码；
 * ——21~80表示县、自治县、旗、自治旗、林区、地区辖特区； ——81~99表示省（自治区）辖县级市。
 * 
 * 15位身份证号码：第7、8位为出生年份(两位数)，第9、10位为出生月份，第11、12位代表出生日期，第15位代表性别，奇数为男，偶数为女。
 * 18位身份证号码：第7、8、9、10位为出生年份(四位数)，第11、第12位为出生月份，第13、14位代表出生日期，第15-17位代表顺序码，顺序码奇数为男，偶数为女。
 * 
 * @author djin
 */
public class IdcardUtil {	
	/**
	 * 18位身份证验证表达式，并不精确，如不存在的地区码、范围外的生日(13月45日？)，可以接受，主要是验证规则
	 */
	private static final Pattern PATTERN = Pattern.compile("^[1-9]\\d{16}[0-9Xx]$");

	/**
	 * 每位加权因子
	 */
	private static final int POWER[] = { 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2 };

	/**
	 * 身份证号码
	 */
	private String idcard = null;

	/**
	 * 身份证验证状态,默认未验证
	 */
	private Boolean verifyFlag = null;

	/**
	 * @param idcard
	 *            身份证号码，如果是15位身份证将自动升为18位身份证
	 */
	public IdcardUtil(String idcard) {
		int length = 15;
		if (idcard != null && idcard.length() == length) {
			this.idcard = this.convertTo18(idcard);
		} else {
			this.idcard = idcard;
		}
	}
	
	/**
	 * 将身份证号码转换为18位，如果身份证号不是15的将返回NULL
	 * @param idcard
	 * @return 返回NULL表示转换失败
	 */
	private String convertTo18(String idcard) {
		int length = 15;
		//不是15位身份证不能转成18位
		if (idcard.length() != length) {
			return null;
		}
		//1900年以前的老人均已过世，2000年以后的人身份证已升级为18位
		String idcard17 = idcard.substring(0, 6) + "19" + idcard.substring(6);
		String x = "x";
		//身份证输入不合法
		if(!validString(idcard17 + x)) {
			return null;
		}
		// 加权求和
		int sum = sumwgt(idcard17);
		// 计算校验码
		String verifyCode = calculateVerifyCode(sum);
		return idcard17+verifyCode;
	}
	
	/**
	 * 验证身份证字符串输入是否合法
	 * @param idcard
	 * @return
	 */
	private boolean validString(String idcard) {
		// 用Pattern方式比idcard.matches("")方式要快3-4倍
		return PATTERN.matcher(idcard).matches();
	}
	
	/**
	 * 加权求和
	 * @param idcard
	 * @return
	 */
	private int sumwgt(String idcard) {
		int sum = 0;
		for (int i = 0; i < POWER.length; i++) {
			// 在ascii中，48表示十进制数字0
			sum += (idcard.charAt(i)-48) * POWER[i];
		}
		return sum;
	}
	
	/**
	 * 计算校验码
	 * @param sum
	 * @return
	 */
	private String calculateVerifyCode(int sum) {
		int mod = sum % 11;
		int code = (12 - mod)%11;
		int ten = 10;
		if(code == ten) {
			return "X";
		}
		return String.valueOf(code);
	}

	/**
	 * <p>
	 * 判断18位身份证的合法性
	 * </p>
	 * 根据〖中华人民共和国国家标准GB11643-1999〗中有关公民身份号码的规定，公民身份号码是特征组合码，由十七位数字本体码和一位数字校验码组成。
	 * 排列顺序从左至右依次为：六位数字地址码，八位数字出生日期码，三位数字顺序码和一位数字校验码。
	 * <p>
	 * 顺序码: 表示在同一地址码所标识的区域范围内，对同年、同月、同 日出生的人编定的顺序号，顺序码的奇数分配给男性，偶数分配 给女性。
	 * </p>
	 * <p>
	 * 1.前1、2位数字表示：所在省份的代码； 2.第3、4位数字表示：所在城市的代码； 3.第5、6位数字表示：所在区县的代码；
	 * 4.第7~14位数字表示：出生年、月、日； 5.第15、16位数字表示：所在地的派出所的代码； 6.第17位数字表示性别：奇数表示男性，偶数表示女性；
	 * 7.第18位数字是校检码：也有的说是个人信息码，一般是随计算机的随机产生，用来检验身份证的正确性。校检码可以是0~9的数字，有时也用x表示。
	 * </p>
	 * <p>
	 * 第十八位数字(校验码)的计算方法为： 1.将前面的身份证号码17位数分别乘以不同的系数。从第一位到第十七位的系数分别为：7 9 10 5 8 4 2 1
	 * 6 3 7 9 10 5 8 4 2
	 * </p>
	 * <p>
	 * 2.将这17位数字和系数相乘的结果相加。
	 * </p>
	 * <p>
	 * 3.用加出来和除以11，看余数是多少？
	 * </p>
	 * 4.余数只可能有0 1 2 3 4 5 6 7 8 9 10这11个数字。其分别对应的最后一位身份证的号码为1 0 X 9 8 7 6 5 4 3 2。
	 * <p>
	 * 5.通过上面得知如果余数是2，就会在身份证的第18位数字上出现罗马数字的Ⅹ。如果余数是10，身份证的最后一位号码就是2。
	 * </p>
	 * 
	 * @return
	 */
	public boolean validate() {
		if (verifyFlag != null) {
			return verifyFlag.booleanValue();
		}
		int length = 18;
		if (idcard == null || idcard.length() != length) {
			verifyFlag = false;
			return verifyFlag;
		}
		
		// 身份证输入不合法
		if (!validString(idcard)) {
			verifyFlag = false;
			return verifyFlag;
		}
		// 获取第18位校验码
		String verifyCode1 = idcard.substring(17, 18);
		// 加权求和
		int sum = sumwgt(idcard);
		// 计算校验码
		String verifyCode2 = calculateVerifyCode(sum);
		if (!verifyCode1.equalsIgnoreCase(verifyCode2)) {
			verifyFlag = false;
		}else {
			verifyFlag = true;
		}
		return verifyFlag;
	}

	/**
	 * 根据身份证获取出生日期
	 * 
	 * @return 如果返回NULL表示身份证校验未通过
	 */
	public Date getBirthday() {
		if (!validate()) {
			return null;
		}
		String birthday = idcard.substring(6, 14);
		try {
			Date birthdate = new SimpleDateFormat("yyyyMMdd").parse(birthday);
			return birthdate;
		} catch (ParseException e) {
			return null;
		}
	}

	/**
	 * 根据身份证获取性别状态
	 * 
	 * @return 0:表示未知，比如身份证校验未通过;1:男;2:女;
	 */
	public int getGender() {
		if (!validate()) {
			return 0;
		}
		String id17 = idcard.substring(16, 17);
		int gender = Integer.valueOf(id17);
		int mod = 2;
		if (gender % mod == 0) {
			return 2;
		} else {
			return 1;
		}
	}
	
	/**
	 * 获取身份证表示的区域码,即身份证的前6位,跟根据国标得到对应的省市区<br/>
	 * 
	 * 国家公布的行政区划码地址：
	 * http://www.mca.gov.cn/article/sj/xzqh/2018/
	 * @return 如果返回0表示身份证校验未通过
	 */
	public int getRegionCode() {
		if (!validate()) {
			return 0;
		}
		String id6 = idcard.substring(0, 6);
		int code = Integer.valueOf(id6);
		return code;
	}
}