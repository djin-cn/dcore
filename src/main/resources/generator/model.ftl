package ${package};
import lombok.Data;
import javax.persistence.OrderBy;
import me.djin.dcore.frame.common.DcoreConstant;

/**
 * @author:djin
 * @date: ${.now}
*/
@Data
public class ${tableClass.shortClassName}${mapperSuffix} {
<#if tableClass.pkFields??>
<#list tableClass.pkFields as field>
    <#if field.fullTypeName == "java.lang.Short">
        <#assign types="java.lang.Integer" />
    <#else>
        <#assign types=field.fullTypeName />
    </#if>
    /**
     * ${field.remarks}
     */
    @javax.persistence.Id
    @OrderBy(DcoreConstant.ORDER_DESC)
    private ${types} ${field.fieldName};
</#list>
</#if>
<#if tableClass.baseFields??>
<#list tableClass.baseFields as field>
    <#if field.fullTypeName == "java.lang.Short">
        <#assign types="java.lang.Integer" />
    <#else>
        <#assign types=field.fullTypeName />
    </#if>
    /**
     * ${field.remarks}
     */
    private ${types} ${field.fieldName};
</#list>
</#if>
}