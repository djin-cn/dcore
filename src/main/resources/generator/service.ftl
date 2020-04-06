package ${package};

import org.springframework.stereotype.Service;
import ${tableClass.fullClassName};

/**
 * @author:djin
 * @date: ${.now}
 */
@Service
public class ${tableClass.shortClassName}${mapperSuffix} implements ${baseMapper!"tk.mybatis.mapper.common.Mapper"}<${tableClass.shortClassName}> {

}