/**
 * 
 */
package me.djin.dcore.id;

/**
 * @author djin
 * ID生成器
 */
public class IdUtil {
	private static final IdGenerator ID_GENERATOR = new Snowflake();
	/**
	 * 生成ID
	 * @return
	 */
	public static final long nextId() {
		return ID_GENERATOR.nextId();
	}
	
	/*public static void main(String[] args) {
		HashSet<Long> ids = new HashSet<Long>();
		int count = 1000000;
		long startMill = System.nanoTime();
		ThreadPoolExecutor pool = new ThreadPoolExecutor(1, count, 3, TimeUnit.SECONDS,
				new ArrayBlockingQueue<>(count),  new ThreadFactoryBuilder()
				.setNameFormat("threadMessage-pool-%d").build());
		for(long i = count; i > 0; i--) {
			pool.execute(new Runnable() {
				@Override
				public void run() {
					long id = nextId();
					ids.add(id);
					System.out.println(id);
					System.out.println("ID数量："+ids.size());
					if(ids.size() == count) {
						long endMill = System.nanoTime();
						System.out.println(endMill-startMill);
						
					}
				}
			});
		}
	}*/
}
