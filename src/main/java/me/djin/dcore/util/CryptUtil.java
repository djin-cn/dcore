package me.djin.dcore.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

/**
 * 加密、解密工具类 包装cipher对象的操作
 * 基于javax.crypto.*、java.security.*、org.apache.commons.codec.binary.Base64实现
 * 解密、加密包装。该工具类仅仅是对底层方法的包装，提供更友好的API使用，本身不包含任何加密、解密 算法；所有加密、解密算法均依赖于JDK提供的包实现；
 * 
 * @author djin
 */
public class CryptUtil {
	/**
	 * 单态实例对象
	 */
	private static final CryptUtil INSTANCE = new CryptUtil();

	/**
	 * 密码类型
	 * 
	 * @author djin
	 *
	 */
	public enum CipherType {
		// AES加密
		AES
	}

	/**
	 * 私有构造函数，避免被外部实例化
	 */
	private CryptUtil() {
	};

	/**
	 * 获取单态实例对象
	 * 
	 * @return
	 */
	public static CryptUtil getInstance() {
		return INSTANCE;
	}

	/**
	 * 产生随机的32位密钥 例如："enM5S1MxcUZTejFnWlpuNUlSamE4dz09"
	 * 
	 * @return 随机密钥
	 */
	public String generateRandomKeyStr(CipherType type) {
		SecretKey key;
		try {
			key = KeyGenerator.getInstance(type.toString()).generateKey();
			return Base64.encodeBase64String(Base64.encodeBase64(key.getEncoded()));
		} catch (NoSuchAlgorithmException e) {
			return null;
		}
	}

	/**
	 * 加密文本, 因为采用的ZeroPadding方式填充, 所以如果原文的首尾包含空字符会自动去除, 即解密后的字符串首尾不包含空字符
	 * 
	 * @param str      明文, 将自动去除首尾空字符
	 * @param password 密钥
	 * @param type     密码类型
	 * @return 密文
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String encrypt(String str, String password, CipherType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		str = str.trim();
		byte[] plainBytes = str.getBytes(StandardCharsets.UTF_8);
		byte[] aesKey = password.getBytes(StandardCharsets.UTF_8);
		int plainLength = plainBytes.length;

		SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key_spec, iv);
		int blockSize = cipher.getBlockSize();

		// 数据长度不是blockSize的整数倍, 需要补位
		int dataLength = plainLength;
		if (dataLength % blockSize != 0) {
			dataLength += blockSize - (dataLength % blockSize);
		}
		byte[] dataBytes = new byte[dataLength];
		// 填充plainBytes到dataBytes, 不足部分自动补位为0;
		System.arraycopy(plainBytes, 0, dataBytes, 0, plainLength);

		byte[] encrypted = cipher.doFinal(dataBytes);
		return Base64.encodeBase64String(encrypted);
	}

	/**
	 * 解密, 因为采用的ZeroPadding方式填充, 所以如果原文的首尾包含空字符会自动去除, 即解密后的字符串首尾不包含空字符
	 * 
	 * @param str      密文
	 * @param password 密钥
	 * @param type     密码算法
	 * @return 明文
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 */
	public String decrypt(String str, String password, CipherType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] aesKey = password.getBytes(StandardCharsets.UTF_8);

		SecretKeySpec key_spec = new SecretKeySpec(aesKey, "AES");
		IvParameterSpec iv = new IvParameterSpec(Arrays.copyOfRange(aesKey, 0, 16));
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, key_spec, iv);

		byte[] encrypted = Base64.decodeBase64(str);
		System.out.println(encrypted.length);
		byte[] original = cipher.doFinal(encrypted);

		return new String(original).trim();
	}

	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		String str = "发行版要点说明新增功能：用于控制加密策略的新安全属性"
				+ "本发行版引入了一项新功能，使得可以通过新安全属性控制 JDK 使用的 JCE 权限策略文件。在以前的发行版中，JCE 权限文件必须单独下载和安装，才能允许 JDK 使用不受限加密。现在，不再需要下载和安装步骤。要启用不受限加密，用户可以使用新的 crypto.policy 安全属性。如果在 java.security 文件中设置了新安全属性 (crypto.policy)，或者在初始化 JCE 框架之前已经使用 Security.setProperty() 调用来动态设置了该安全属性，则将遵循该设置。默认情况下，此属性未定义。如果此属性未定义，并且传统 lib/security 目录中不存在传统的 JCE 权限文件，则默认加密级别将保留为“受限”。要将 JDK 配置为使用不受限加密，请将 crypto.policy 设置为“无限制”值。有关详细信息，请参阅本发行版随附的 java.security 文件中的说明。"
				+ "注：在 Solaris 上，建议删除旧 SVR4 包，然后再安装新的 JDK 更新。如果在早于 6u131、7u121、8u111 的 JDK 发行版上完成了基于 SVR4 的升级（不卸载旧包），则您应在 java.security 文件中设置新的 crypto.policy 安全属性。";
		String password = CryptUtil.getInstance().generateRandomKeyStr(CipherType.AES);
		System.err.println(password);
		String encrypt = CryptUtil.getInstance().encrypt(str, password, CipherType.AES);
		System.out.println(encrypt);
		String decrypt = CryptUtil.getInstance().decrypt(encrypt, password, CipherType.AES);
		System.out.println(decrypt);
		System.out.println("加解密成功:" + decrypt.equals(str));
	}
}
