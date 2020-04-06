# dcore框架说明
　　框架以Spring Boot2.1.3+Mybatis为基础,集成邮件发送/Redis/Swagger/通用Service/通用DAO/ID生成等常用功能, 简化项目开发
  
## 目录结构说明
1. me.djin.dcore: 所有代码的根目录, 以下结构均继承自此目录下, 不单独说明
2. aspect: 切面注入包
3. core: 核心包, 原目的是为了减轻对Spring系列的依赖但未成功
4. exception: 异常包, 包含ApplicationException异常类, 建议抛出异常时都抛出此异常
5. frame: 常用的Servcie/DAO/Model/Test等基类
6. id: ID生成器模块
7. mail: 邮件模块
8. message: 消息内容相关的包
9. mq: MQ模块, 包含了Kafka实现和Thread实现, 默认为thread
10. mybatis: Mybatis相关扩展, 目前包含PGSQL数据库的JSON类型支持, 支持将Map类型转换为JSONB类型
11. quartz: 计划用于定时任务, 支持分布式
12. redis: Redis的常用操作
13. swagger: Swagger模块封装
14. util: 常用的工具类

## 配置文件说明
　　dcore默认自带了application.properties, 此配置包含了一些默认的配置, 所以应用此框架的项目一般情况不需要创建application.properties. 默认配置包括了Tomcat常用配置/Mybatis配置/Redis配置/数据库配置(默认pgsql, localhost:5432, 账号密码:postgres/123456)/MQ/日志等常用配置, 具体配置项可以查看配置文件    

　　通常我们需要自定义配置, 我们可以通过application-default.properties定义, 在application.properties配置文件中有一项配置spring.profiles.include=default默认引入了application-default.properties配置文件.  

　　通常建议通过application-{运行环境}.properties方式命名配置文件, 这样的好处是可以在不同的环境使用不同的配置, 而不需要在切换环境时重新修改配置文件, 常用的运行环境有{dev:开发环境, 个人开发时使用; debug: 联调环境, 一般和前端等联调或者联合开发时用; test: 测试环境时使用; prod: 生产环境时使用; default: 默认的配置文件, 所有环境通用}

## 常用文件介绍
1. 引入dcore框架
2. 添加默认的配置文件application-default.properties
3. 常用类()
   1. CurdBaseDao: 基础数据访问接口，提供数据库基础访问操作, 但不包含批量添加、删除操作  
   2. CurdDao: 继承自CurdBaseDao接口, 包含批量添加、删除操作. 和CurdBaseDao一样,是所有DAO的基类  
   3. CurdService: 础服务接口，提供常规增删改查服务, 所有Service的基类  
   4. DcoreConstant: 框架全局常量类, 包含排序方式等常量  
   5. GlobalExceptionHandler: 全局异常类, 主要目的防止系统对外抛出莫名异常  
   6. RequestParams: 全局请求参数类, 可获取pn/pc/当前登录用户/客户端IP等去全局请求参数  
   7. ValidatorUtil: 验证工具类, 主要用于手动调用参数校验的情况  
   8. IdUtil: ID生成器, 可通过IdUtil.nextId()生成ID  
   9. PgsqlJsonTypeHandler: postgresql数据库json类型字段处理, 需要在实体类对应的字段上添加@ColumnType(typeHandler=PgsqlJsonTypeHandler.class)  
4. 常用MODEL
   1. CurrentUser: 当前用户MODEL, 前端需要设置Authorization请求头, 后端可通过RequestParams.getCurrentUser()获取  
   2. IdListModel: ID列表MODEL, 主要用于API接口参数接收  
   3. IdModel: ID MODEL, 主要用于API接口参数接收  
   4. KeywordQueryModel: 关键词MODEL, 主要用于API接口参数接收  
   5. PageModel: 分页MODEL, 主要用于封装分页对象  
   6. QueryModel: 通用查询MODEL, 包含了排序属性, 建议所有数据查询VO都继承自此MODEL  
   7. Response: 通用响应模型, 主要用于API接口返回  
5. 自定义验证注解
   1. @Idcard: 验证身份证号码, 支持15位和18位身份证号码校验

## 使用示例
1. 如何生成ID  
IdUtil.nextId()
2. 接口返回统一的响应格式  
Response.ok(): 返回正确的响应, 可带参数指定返回的数据  
Response.error(): 返回失败的响应, 可带参数制定错误码  
