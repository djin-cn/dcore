/**
 * 
 */
package me.djin.dcore.id;

import java.net.InetAddress;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import me.djin.dcore.util.HostUtils;

/**
 * @author djin
 * Snowflake算法，原算法理论:<br/>
 * long长度为64位，对64位长度进行拆分，<br/>
 * 1位符号位，永远为0；<br/>
 * 41位时间码，存储时间戳，这里的时间戳不是要从1970年开始算起，可以自己设定一个开始时间，计算时间戳差即可，41位时间戳可以用68年；<br/>
 * 10位机器码，可以部署2^10=1024个局点；<br/>
 * 12位序号码，记录一毫秒内产生的ID，顺序递增，1毫秒可以产生2^12=4096个ID。<br/>
 * 
 * 以上为网上摘录的原算法，可以基于此进行一些变种。如原算法机器编码需要手动设定，我们可以想办法自动生成等等。<br/>
 * 
 * 上述原算法时间码为时间戳，12位序号码，一台服务器每秒可产生4096*1000=409.6万IP，暂时没有这个条件达到这个水准；
 * 机器码可根据服务器的IP或者MAC地址自动生成，但是10位不够用；
 * 所以我们对算法稍微做了一点改动：
 * 1位符号位，永远为0；<br/>
 * 32位时间码，存储秒钟，可以自行设定一个开始时间，计算两者之间的秒数即可，可用136年；<br/>
 * 16为机器码，可部署2^16=65536个局点，且方便根据IP计算机器码，注意：此方式掩码必须为16，即IP只变后两位，前两位不便，否则可能会出现ID冲突问题；<br/>
 * 15位序号码，可生成2^15=32768个ID，1秒钟3万ID基本够用；<br/>
 */
public class Snowflake implements IdGenerator {
	private static final Logger LOGGER = LoggerFactory.getLogger(Snowflake.class);
	/**
	 * 最小时间戳2018-01-01 00:00:00
	 */
	private static final long MIN_TIMESTAMP = 1514764800L;
	/**
	 * 序号码位数
	 */
	private static final int SEQUENCE_BIT = 15;
	/**
	 * 机器码位数
	 */
	private static final int MAC_BIT=16;
	/**
	 * 最大序号
	 */
	private static final int SEQUENCE_MASK = -1 ^ (-1 << SEQUENCE_BIT);
	
	/**
	 * 序号
	 */
	private static int sequence = 0;
	/**
	 * 最后时间码
	 */
	private static long latestTimeCode = 0L;
	/**
	 * 当前机器码
	 */
	private static int machineCode = -1;
	
	/**
	 * 获取机器码
	 * @return
	 */
	private int getMachineCode() {
		if(machineCode != -1) {
			return machineCode;
		}
		InetAddress addr = null;
		try {
			addr = HostUtils.getLanInetAddress();
		} catch (RuntimeException e) {
			throw new RuntimeException("IdGenerator can not get ip", e);
		}
		byte[] ip = addr.getAddress();
		int ipLen = 4;
		if(ip.length != ipLen) {
			throw new RuntimeException("IdGenerator can not support this ip:"+addr.getHostAddress());
		}
		LOGGER.info("IdGenerator's IP is: " + addr.getHostAddress());
		
		machineCode = ((ip[2]&0xff)<<8) | (ip[3]&0xff);
		return machineCode;
	}
	/**
	 * 获取时间码
	 * @return
	 */
	private long getTimeCode() {
		long timestamp = System.currentTimeMillis()/1000-MIN_TIMESTAMP;
		if(timestamp < 0) {
			throw new RuntimeException("Invalid time of IdGenerator server");
		}
		return timestamp;
	}
	/**
	 * 获取序号,如果返回0表示ID已用完
	 * @return
	 */
	private int getSequenceCode() {
		sequence = (sequence + 1) & SEQUENCE_MASK;
		return sequence;
	}
	
	@Override
	public synchronized long nextId() {
		long timeCode = getTimeCode();
		int macCode = getMachineCode();
		if(timeCode > latestTimeCode) {
			sequence = 0;
			latestTimeCode = timeCode;
		} else {
			sequence = getSequenceCode();
			//如果seqCode已用完，循环获取下一个ID
			if(sequence == 0) {
				while(timeCode == latestTimeCode) {
					timeCode = getTimeCode();
				}
				latestTimeCode = timeCode;
			}			
		}
		return timeCode << (SEQUENCE_BIT + MAC_BIT) | macCode << SEQUENCE_BIT | sequence;
	}
	
	/*public static void main(String[] args) {
		HashSet<Long> ids = new HashSet<Long>();
		Snowflake idg = new Snowflake();
		int count = 1000000;
		ThreadPoolExecutor pool = new ThreadPoolExecutor(1, count, 3, TimeUnit.SECONDS,
				new ArrayBlockingQueue<>(count),  new ThreadFactoryBuilder()
				.setNameFormat("threadMessage-pool-%d").build());
		for(long i = count; i > 0; i--) {
			pool.execute(new Runnable() {
				@Override
				public void run() {
					long id = idg.nextId();
					ids.add(id);
					System.out.println(id);
					System.out.println("ID数量："+ids.size());
				}
			});
		}
	}*/
}