
# 前言

最近学习研究一下目前业内主流的 JavaWeb 内存马实现方式，并探究完美的查杀的方法。

本文前几章是基础知识学习和研究记录，如果你对内存马很熟悉，可以选择跳过，直接看后面对攻防思路的讨论。

本文的部分实现已上传至 Github：[https://github.com/su18/MemoryShell](https://github.com/su18/MemoryShell)



# 前世今生

内存马又名无文件马，见名知意，指的是无文件落地的webshell；由于传统的webshell需要写入文件，难以逃避防篡改监控。为了与传统的防御手段对抗，衍生出了一种新型的内存WebShell技术，其核心思想用一句话概括，即：利用类加载或Agent机制在JavaEE、框架或中间件的API中动态注册一个可访问的后门。

这种动态注册技术来源非常久远，在安全行业里也一直是不温不火的状态，直到冰蝎的更新将 java agent 类型的内存马重新带入大众视野并且瞬间火爆起来。这种技术的爆红除了概念新颖外，也确实符合时代发展潮流，现在针对 webshell 的查杀和识别已经花样百出，大厂研发的使用分类、概率等等方式训练的机器学习算法模型，基于神经网络的流量层面的特征识别手段，基本上都花式吊打常规文件型 webshell。如果你不会写，不会绕，还仅仅使用网上下载的 jsp ，那肯定是不行的。

内存马搭上了冰蝎和反序列化漏洞的快车，快速占领了人们的视野，成为了主流的 webshell 写入方式。作为 RASP 技术的使用者，自然也要来研究和学习一下内存马的思想、原理、添加方式，并探究较好、较通用的防御和查杀方式。

目前安全行业主要讨论的内存马主要分为以下几种方式：

- 动态注册 servlet/filter/listener（使用 servlet-api 的具体实现）
- 动态注册 interceptor/controller（使用框架如 spring/struts2）
- 动态注册使用**职责链**设计模式的中间件、框架的实现（例如 Tomcat 的 Pipeline & Valve，Grizzly 的 FilterChain & Filter 等等）
- 使用 java agent 技术写入字节码




# 写入测试

本章进行完整的内存马写入的学习测试记录。

## Servlet API 提供的动态注册机制

早在 2013 年，国际大站 p2j 就发布了这种特性的一种使用方法：

![img](https://oss.javasec.org/images/1623378669097.png)

Servlet、Listener、Filter 由 `javax.servlet.ServletContext` 去加载，无论是使用 xml 配置文件还是使用 Annotation 注解配置，均由 Web 容器进行初始化，读取其中的配置属性，然后向容器中进行注册。

Servlet 3.0 API 允许使 ServletContext 用动态进行注册，在 Web 容器初始化的时候（即建立ServletContext 对象的时候）进行动态注册。可以看到 ServletContext 提供了 add*/create* 方法来实现动态注册的功能。

![img](https://oss.javasec.org/images/1623383074795.png)

在不同的容器中，实现有所不同，这里仅以 Tomcat 为例调试，其他中间件在代码中有部分实现，请师傅自行观看。

### Filter 内存马

Filter 我们称之为过滤器，是 Java 中最常见也最实用的技术之一，通常被用来处理静态 web 资源、访问权限控制、记录日志等附加功能等等。一次请求进入到服务器后，将先由 Filter 对用户请求进行预处理，再交给 Servlet。

通常情况下，Filter 配置在配置文件和注解中，在其他代码中如果想要完成注册，主要有以下几种方式：
1. 使用 ServletContext 的 addFilter/createFilter 方法注册；
2. 使用 ServletContextListener 的 contextInitialized 方法在服务器启动时注册（将会在 Listener 中进行描述）；
3. 使用 ServletContainerInitializer 的 onStartup 方法在初始化时注册（非动态，后面会描述）。

本节只讨论使用 ServletContext 添加 Filter 内存马的方法。首先来看一下 `createFilter` 方法，按照注释，这个类用来在调用 `addFilter` 向 ServletContext 实例化一个指定的 Filter 类。

![img](https://oss.javasec.org/images/1623412713625.png)

这个类还约定了一个事情，那就是如果这个 ServletContext 传递给 ServletContextListener 的 ServletContextListener.contextInitialized 方法，该方法既未在 web.xml 或 web-fragment.xml 中声明，也未使用 javax.servlet.annotation.WebListener 进行注释，则会抛出 UnsupportedOperationException 异常，这个约定其实是非常重要的一点。

接下来看 `addFilter` 方法，ServletContext 中有三个重载方法，分别接收字符串类型的 filterName 以及 Filter 对象/className 字符串/Filter 子类的 Class 对象，提供不同场景下添加 filter 的功能，这些方法均返回 `FilterRegistration.Dynamic` 实际上就是 FilterRegistration 对象。

`addFilter` 方法实际上就是动态添加 filter 的最核心和关键的方法，但是这个类中同样约定了 UnsupportedOperationException 异常。

由于 Servlet API 只是提供接口定义，具体的实现还要看具体的容器，那我们首先以 Tomcat 7.0.96 为例，看一下具体的实现细节。相关实现方法在 `org.apache.catalina.core.ApplicationContext#addFilter` 中。

![img](https://oss.javasec.org/images/1623553440934.png)

可以看到，这个方法创建了一个 FilterDef 对象，将 filterName、filterClass、filter 对象初始化进去，使用 StandardContext 的 `addFilterDef` 方法将创建的 FilterDef 储存在了 StandardContext 中的一个 Hashmap filterDefs 中，然后 new 了一个 ApplicationFilterRegistration 对象并且返回，并没有将这个 Filter 放到 FilterChain 中，单纯调用这个方法不会完成自定义 Filter 的注册。并且这个方法判断了一个状态标记，如果程序以及处于运行状态中，则不能添加 Filter。

这时我们肯定要想，能不能直接操纵 FilterChain 呢？FilterChain 在 Tomcat 中的实现是 `org.apache.catalina.core.ApplicationFilterChain`，这个类提供了一个 `addFilter` 方法添加 Filter，这个方法接受一个 ApplicationFilterConfig 对象，将其放在 `this.filters` 中。答案是可以，但是没用，因为对于每次请求需要执行的 FilterChain 都是动态取得的。

那Tomcat 是如何处理一次请求对应的 FilterChain 的呢？在 ApplicationFilterFactory 的 `createFilterChain` 方法中，可以看到流程如下：

- 在 context 中获取 filterMaps，并遍历匹配 url 地址和请求是否匹配；
- 如果匹配则在 context 中根据 filterMaps 中的 filterName 查找对应的 filterConfig；
- 如果获取到 filterConfig，则将其加入到 filterChain 中
- 后续将会循环 filterChain 中的全部 filterConfig，通过 `getFilter` 方法获取 Filter 并执行 Filter 的 `doFilter` 方法。

通过上述流程可以知道，每次请求的 FilterChain 是动态匹配获取和生成的，如果想添加一个 Filter ，需要在 StandardContext 中 filterMaps 中添加 FilterMap，在 filterConfigs 中添加 ApplicationFilterConfig。这样程序创建时就可以找到添加的 Filter 了。

在之前的 ApplicationContext 的 addFilter 中将 filter 初始化存在了 StandardContext 的 filterDefs 中，那后面又是如何添加在其他参数中的呢？

在 StandardContext 的 `filterStart` 方法中生成了 filterConfigs。

![img](https://oss.javasec.org/images/1623566822352.png)

在 ApplicationFilterRegistration 的 `addMappingForUrlPatterns` 中生成了 filterMaps。

![img](https://oss.javasec.org/images/1623566974104.png)

而这两者的信息都是从 filterDefs 中的对象获取的。

在了解了上述逻辑后，在应用程序中动态的添加一个 filter 的思路就清晰了：

- 调用 ApplicationContext 的 addFilter 方法创建 filterDefs 对象，需要反射修改应用程序的运行状态，加完之后再改回来；
- 调用 StandardContext 的 filterStart 方法生成 filterConfigs；
- 调用 ApplicationFilterRegistration 的 addMappingForUrlPatterns 生成 filterMaps；
- 为了兼容某些特殊情况，将我们加入的 filter 放在 filterMaps 的第一位，可以自己修改 HashMap 中的顺序，也可以在自己调用 StandardContext 的 addFilterMapBefore 直接加在 filterMaps 的第一位。

基于以上思路的实现在 threedr3am 师傅的[这篇文章](https://xz.aliyun.com/t/7388)中有实现代码，我这里不再重复，而且这种实现方式也不适合我，既然知道了需要修改的关键位置，那就没有必要调用方法去改，直接用反射加进去就好了，其中中间还有很多小细节可以变化，但都不是重点，略过。

写一个 demo 模拟一下动态添加一个 filter 的过程。首先我们有一个 IndexServlet，如果请求参数有 id 的话，则打印在页面上。

![img](https://oss.javasec.org/images/1623559164607.png)

现在我们想实现在程序运行过程中动态添加一个 filter ，提供将 id 参数的数字值 + 3 的功能（随便瞎想的功能。）具体代码放在了 `org.su18.memshell.web.servlet.AddTomcatFilterServlet` 中，这里由于篇幅原因就不贴了。

普通访问时，会将 id 的值打印出来。

![img](https://oss.javasec.org/images/1623565922927.png)

访问添加 filter。

![img](https://oss.javasec.org/images/1623565973421.png)

再次访问，id 参数会被加三。

![img](https://oss.javasec.org/images/1623566012255.png)

### Servlet 内存马

Servlet 是 Server Applet（服务器端小程序）的缩写，用来读取客户端发送的数据，处理并返回结果。也是最常见的 Java 技术之一。

与 Filter 相同，本小节也仅仅讨论使用 ServletContext 的相关方法添加 Servlet。还是首先来看一下实现类 ApplicationContext 的 `addServlet` 方法。

![img](https://oss.javasec.org/images/1623571128390.png)

与上一小节看到的 `addFilter` 方法十分类似。那么我们面临同样的问题，在一次访问到达 Tomcat 时，是如何匹配到具体的 Servlet 的？这个过程简单一点，只有两部走：

- ApplicationServletRegistration 的 `addMapping` 方法调用 `StandardContext#addServletMapping` 方法，在 mapper 中添加 URL 路径与 Wrapper 对象的映射（Wrapper 通过 this.children 中根据 name 获取）
- 同时在 servletMappings 中添加 URL 路径与 name 的映射。

这里直接调用相关方法进行添加，当然是用反射直接写入也可以，有一些逻辑较为复杂。测试代码在 `org.su18.memshell.web.servlet.AddTomcatServlet` 中，访问这个 servlet 会在程序中生成一个新的 Servlet :`/su18`。

![img](https://oss.javasec.org/images/1623575000562.png)

看一下效果。

![img](https://oss.javasec.org/images/1623574985705.png)

### Listener 内存马

Servlet 和 Filter 是程序员常接触的两个技术，所以在网络上对于之前两小节的讨论较多，对于 Listener 的讨论较少。但实际上这个点还是有很多师傅关注到了。

Listener 可以译为监听器，监听器用来监听对象或者流程的创建与销毁，通过 Listener，可以自动触发一些操作，因此依靠它也可以完成内存马的实现。先来了解一下 Listener 是干什么的，看一下 Servlet API 中的注释。

![img](https://oss.javasec.org/images/1623576978964.png)

在应用中可能调用的监听器如下：

- ServletContextListener：用于监听整个 Servlet 上下文（创建、销毁）
- ServletContextAttributeListener：对 Servlet 上下文属性进行监听（增删改属性）
- ServletRequestListener：对 Request 请求进行监听（创建、销毁）
- ServletRequestAttributeListener：对 Request 属性进行监听（增删改属性）
- javax.servlet.http.HttpSessionListener：对 Session 整体状态的监听
- javax.servlet.http.HttpSessionAttributeListener：对 Session 属性的监听

可以看到 Listener 也是为一次访问的请求或生命周期进行服务的，在上述每个不同的接口中，都提供了不同的方法，用来在监听的对象发生改变时进行触发。而这些类接口，实际上都是 `java.util.EventListener` 的子接口。这里我们看到，在 ServletRequestListener 接口中，提供了两个方法在 request 请求创建和销毁时进行处理，比较适合我们用来做内存马。

![img](https://oss.javasec.org/images/1623578410672.png)

而除了这个 Listener，其他的 Listener 在某些情况下也可以触发作为内存马的实现，本篇文章里不会对每个都进行触发测试，感兴趣的师傅可以自测。

ServletRequestListener 提供两个方法：`requestInitialized` 和 `requestDestroyed`，两个方法均接收 ServletRequestEvent 作为参数，ServletRequestEvent 中又储存了 ServletContext 对象和 ServletRequest 对象，因此在访问请求过程中我们可以在 request 创建和销毁时实现自己的恶意代码，完成内存马的实现。

![img](https://oss.javasec.org/images/1623640456652.png)

Tomcat 中 EventListeners 存放在 StandardContext 的 applicationEventListenersObjects 属性中，同样可以使用 StandardContext 的相关 add 方法添加。

我们还是实现一个简单的功能，在 requestDestroyed 方法中获取 response 对象，向页面原本输出多写出一个字符串。正常访问时：

![img](https://oss.javasec.org/images/1623641922533.png)

添加 Listener，可以看到，由于我们是在 requestDestroyed 中植入恶意逻辑，那么在本次请求中就已经生效了：

![img](https://oss.javasec.org/images/1623641951941.png)

访问之前的路径也生效了：

![img](https://oss.javasec.org/images/1623642002784.png)

除了 EventListener，Tomcat 还存在了一个 LifecycleListener ，当然也肯定有可以用来触发的实现类，但是用起来一定是不如 ServletRequestListener ，但是也可以关注一下。这里将不会进行演示。

由于在 ServletRequestListener 中可以获取到 ServletRequestEvent，这其中又存了很多东西，ServletContext/StandardContext 都可以获取到，那玩法就变得更多了。可以根据不同思路实现很多非常神奇的功能，我举个例子：

- 在 requestInitialized 中监听，如果访问到了某个特定的 URL，或这次请求中包含某些特征（可以拿到 request 对象，随便怎么定义），则新起一个线程去 StandardContext 中注册一个 Filter，可以实现某些恶意功能。
- 在 requestDestroyed 中再起一个新线程 sleep 一定时间后将我们添加的 Filter 卸载掉。

这样我们就有了一个真正的动态后门，只有用的时候才回去注册它，用完就删。平常使用扫内存马的软件也根本扫不出来。这个例子也是我突然拍脑袋想出来的，可能实际意义并不大，但是可以看出 Listener 内存马的危害性和玩法的变化要大于 Filter/Servlet 内存马的。

## 控制器、拦截器、管道

在上一章节中，我们分析了 Servlet API 中提供的能够利用实现内存马的一些点。总结来说：

- Servlet ：在用户请求路径与处理类映射之处，添加一个指定路径的指定处理类；
- Filter：在用户处理类之前的，用来对请求进行额外处理提供额外功能的类；
- Listener：在 Filter 之外的监听进程。

那么除了 Servlet API ，其实在常用的框架、组件、中间件的实现中，只要采用了类似的设计思想和设计模式的位置，都可以、逐渐或正在被发掘出来做为内存马的相关实现。

本章就是其中的几个例子。

### Spring Controller 内存马

Servlet 能做内存马，Controller 当然也能做，不过 SpringMVC 可以在运行时动态添加 Controller 吗？答案是肯定的。在动态注册 Servlet 时，注册了两个东西，一个是 Servlet 的本身实现，一个 Servlet 与 URL 的映射 Servlet-Mapping，在注册 Controller 时，也同样需要注册两个东西，一个是 Controller，一个是 RequestMapping 映射。这里使用 spring-webmvc-5.2.3 进行调试。

所谓 Spring Controller 的动态注册，就是对 RequestMappingHandlerMapping 注入的过程，如果你对 SpringMVC 比较了解，可以直接看[这篇文章](https://blog.csdn.net/ywg_1994/article/details/112800703)然后再看我的注入代码，如果比较关注整个流程，可以接着向下看。

首先来看两个类：

- RequestMappingInfo：一个封装类，对一次 http 请求中的相关信息进行封装。
- HandlerMethod：对 Controller 的处理请求方法的封装，里面包含了该方法所属的 bean、method、参数等对象。

SpringMVC 初始化时，在每个容器的 bean 构造方法、属性设置之后，将会使用 InitializingBean 的 `afterPropertiesSet` 方法进行 Bean 的初始化操作，其中实现类 RequestMappingHandlerMapping 用来处理具有 `@Controller` 注解类中的方法级别的 `@RequestMapping` 以及 RequestMappingInfo 实例的创建。看一下具体的是怎么创建的。

它的 `afterPropertiesSet` 方法初始化了 RequestMappingInfo.BuilderConfiguration 这个配置类，然后调用了其父类 AbstractHandlerMethodMapping 的 `afterPropertiesSet` 方法。

![img](https://oss.javasec.org/images/1623734468541.png)

这个方法调用了 initHandlerMethods 方法，首先获取了 Spring 中注册的 Bean，然后循环遍历，调用 `processCandidateBean` 方法处理 Bean。

![img](https://oss.javasec.org/images/1623735423292.png)

`processCandidateBean` 方法

![img](https://oss.javasec.org/images/1623735638214.png)

`isHandler` 方法判断当前 bean 定义是否带有 Controller 或 RequestMapping 注解。

![img](https://oss.javasec.org/images/1623735310283.png)

`detectHandlerMethods` 查找 handler methods 并注册。

![img](https://oss.javasec.org/images/1623735988861.png)

这部分有两个关键功能，一个是 `getMappingForMethod` 方法根据 handler method 创建RequestMappingInfo 对象，一个是 `registerHandlerMethod` 方法将 handler method 与访问的 创建 RequestMappingInfo 进行相关映射。

![img](https://oss.javasec.org/images/1623736666146.png)

这里我们看到，是调用了 MappingRegistry 的 register 方法，这个方法将一些关键信息进行包装、处理和储存。

![img](https://oss.javasec.org/images/1623736616923.png)

关键信息储存位置如下：

![img](https://oss.javasec.org/images/1623736988351.png)

以上就是整个注册流程，那当一次请求进来时的查找流程呢？在 AbstractHandlerMethodMapping 的 lookupHandlerMethod 方法：

- 在 MappingRegistry.urlLookup 中获取直接匹配的 RequestMappingInfos
- 如果没有，则遍历所有的 MappingRegistry.mappingLookup 中保存的 RequestMappingInfos
- 获取最佳匹配的 RequestMappingInfo 对应的 HandlerMethod

上述的流程和较详细的流程描述在[这篇文章](https://www.cnblogs.com/w-y-c-m/p/8416630.html)中可以查看，由于我这里使用的版本与之不同，所以一些代码和细节可能不同。

那接下来就是动态注册 Controller 了，LandGrey 师傅在[他的文章](https://landgrey.me/blog/12/)中列举了几种可用来添加的接口，其实本章上都是调用之前我们提到的 MappingRegistry 的 register 方法。

和 Servlet 的添加较为类似的是，重点需要添加的就是访问 url 与 RequestMappingInfo 的映射，以及是 RequestMappingInfo 与 HandlerMethod 的映射。

这里我不会使用 LandGrey 师傅提到的接口，而是直接使用 MappingRegistry 的 register 方法来添加，当然，同样可以通过自己实现逻辑，通过反射直接写进重要位置，不使用 Spring 提供的接口。

正常访问 indexController

![img](https://oss.javasec.org/images/1623757300676.png)

动态添加 Controller

![img](https://oss.javasec.org/images/1623757305546.png)

访问添加的 Controller

![img](https://oss.javasec.org/images/1623757310626.png)

这里注意的是，在不同版本中，参数名、调用细节都有不同。

### Spring Interceptor 内存马

这里的描述的 Intercepor 是指 Spring 中的拦截器，它是 Spring 使用 AOP 对 Filter 思想的令一种实现，在其他框架如 Struts2 中也有拦截器思想的相关实现。不过这里将仅仅使用 Spring 中的拦截器进行研究。Intercepor 主要是针对 Controller 进行拦截。

Intercepor 是在什么时候调用的呢？又配置储存在哪呢？这部分比较简单，直接用文字来描述一下这个过程：

- Spring MVC 使用 DispatcherServlet 的 `doDispatch` 方法进入自己的处理逻辑；
- 通过 `getHandler` 方法，循环遍历 `handlerMappings` 属性，匹配获取本次请求的 HandlerMapping；
- 通过 HandlerMapping 的 `getHandler` 方法，遍历 `this.adaptedInterceptors` 中的所有 HandlerInterceptor 类实例，加入到 HandlerExecutionChain 的 interceptorList 中；
- 调用 HandlerExecutionChain 的 applyPreHandle 方法，遍历其中的 HandlerInterceptor 实例并调用其 preHandle 方法执行拦截器逻辑。

通过这次流程我们就清晰了，拦截器本身需要是 HandlerInterceptor 实例，储存在 AbstractHandlerMapping 的 adaptedInterceptors 中。写入非常简单，直接上例子。

正常访问

![img](https://oss.javasec.org/images/1623808912048.png)

添加拦截器

![img](https://oss.javasec.org/images/1623808919546.png)

再次访问

![img](https://oss.javasec.org/images/1623808925115.png)

### Tomcat Valve 内存马

Tomcat 在处理一个请求调用逻辑时，是如何处理和传递 Request 和 Respone 对象的呢？为了整体架构的每个组件的可伸缩性和可扩展性，Tomcat 使用了职责链模式来实现客户端请求的处理。在 Tomcat 中定义了两个接口：Pipeline（管道）和 Valve（阀）。这两个接口名字很好的诠释了处理模式：数据流就像是流经管道的水一样，经过管道上个一个个阀门。

Pipeline 中会有一个最基础的 Valve（basic），它始终位于末端（最后执行），封装了具体的请求处理和输出响应的过程。Pipeline 提供了 `addValve` 方法，可以添加新 Valve 在 basic 之前，并按照添加顺序执行。

![img](https://oss.javasec.org/images/1623645442719.jpg)

Tomcat 每个层级的容器（Engine、Host、Context、Wrapper），都有基础的 Valve 实现（StandardEngineValve、StandardHostValve、StandardContextValve、StandardWrapperValve），他们同时维护了一个 Pipeline 实例（StandardPipeline），也就是说，我们可以在任何层级的容器上针对请求处理进行扩展。这四个 Valve 的基础实现都继承了 ValveBase。这个类帮我们实现了生命接口及MBean 接口，使我们只需专注阀门的逻辑处理即可。

先来简单看一下接口的定义，`org.apache.catalina.Pipeline` 的定义如下：

![img](https://oss.javasec.org/images/1623646288477.png)

`org.apache.catalina.Valve` 的定义如下：

![img](https://oss.javasec.org/images/1623646342704.png)

具体实现的代码逻辑在[这篇文章](https://www.cnblogs.com/coldridgeValley/p/5816414.html)描述的比较好。

Tomcat 中 Pipeline 仅有一个实现 StandardPipeline，存放在 ContainerBase 的 pipeline 属性中，并且 ContainerBase 提供 `addValve` 方法调用 StandardPipeline 的 addValve 方法添加。

![img](https://oss.javasec.org/images/1623647163683.png)

Tomcat 中四个层级的容器都继承了 ContainerBase ，所以在哪个层级的容器的标准实现上添加自定义的 Valve 均可。

添加后，将会在 `org.apache.catalina.connector.CoyoteAdapter` 的 `service` 方法中调用 Valve 的 `invoke` 方法。

![img](https://oss.javasec.org/images/1623648233517.png)

这里我们只要自己写一个 Valve 的实现类，为了方便也可以直接使用 ValveBase 实现类。里面的 `invoke` 方法加入我们的恶意代码，由于可以拿到 Request 和 Response 方法，所以也可以做一些参数上的处理或者回显。然后使用 StandardContext 中的 pipeline 属性的 addValve 方法进行注册。

首先正常访问：

![img](https://oss.javasec.org/images/1623649463332.png)

动态添加自定义恶意 Valve，会先调用 response 写入字符串

![img](https://oss.javasec.org/images/1623649411692.png)

再次访问出现效果：

![img](https://oss.javasec.org/images/1623649401840.png)

如果对管道和阀的定义理解困难的话，按照 FilterChain 和 Filter 的关系来理解也可。

### GlassFish Grizzly Filter 内存马

GlassFish 使用 grizzly 组件来完成 NIO 的工作，类似 Tomcat 中的 connector 组件。在 HTTP 下，grizzly 负责解析和序列化 HTTP 请求/响应，grizzly 有职责链设计模式的体现，提供了 Filter 和 FilterChain 等接口及实现，就可以被用来写入内存马。

中间的实现过程有较多难点和细节，这里不占篇幅分析，感兴趣的师傅自行观看代码实现。我们直接来看一下效果，添加之后随便访问页面，发现结果被成功写回：

![img](https://oss.javasec.org/images/1624019245038.png)

## 基于字节码修改的字节码

### Java Agent 内存马

哈哈哈哈哈哈哈哈哈 java agent 内存马哈哈哈哈哈哈哈哈哈哈哈哈哈哈，又有谁能够想到， java agent 技术能被用来写内存马吗？哈哈哈哈哈哈哈哈哈哈哈哈哈哈隔，花里胡哨。

Java Agent 技术我这里不再介绍，我写过一篇[学习笔记](https://su18.org/post/irP0RsYK1/)，总体来说就是可以使用 Instrumentation 提供的 retransform 或 redefine 来动态修改 JVM 中 class 的一种字节码增强技术，可以直接理解为，这是 JVM 层面的一个拦截器。这里直接来看一下内存马的实现。

首先是冰蝎作者 rebeyond 师傅，[他的项目](https://github.com/rebeyond/memShell)提出了这种想法，在这个项目中，他 hook 了 Tomcat 的 ApplicationFilterChain 的 `internalDoFilter`方法。

![img](https://oss.javasec.org/images/1623823221923.png)

使用 javassist 在其中插入了自己的判断逻辑，也就是项目的 ReadMe 中 usage 中提供的一些逻辑，

![img](https://oss.javasec.org/images/1623824044934.png)

也就是说在 Tomcat 调用 ApplicationFilterChain 对请求调用 filter 链处理之前加入恶意逻辑。

师傅在冰蝎中同样加入了内存马的功能的实现，调用代码位置 `net.rebeyond.behinder.payload.java.MemShell`，目前对于 Servlet 和 Filter 还是空实现，可能是后续要加的功能？

![img](https://oss.javasec.org/images/1623829223756.png)

agent 端在 net/rebeyond/behinder/resource/tools 中，应该是根据不同的类型会上传不同的注入包。

![img](https://oss.javasec.org/images/1623826322201.png)

但是这次不再 Hook Tomcat 的方法，而是选择 Hook 了 Servlet-API 中更具有通用性的 `javax.servlet.http.HttpServlet` 的 `service` 方法，如果检测出是 Weblogic，则选择 Hook `weblogic.servlet.internal.ServletStubImpl` 方法。

![img](https://oss.javasec.org/images/1623828945298.png)

那么说到这里，使用插桩技术的 RASP、IAST 的使用者一下就可以明白：如果都能做到这一步了，能玩的就太多了。能下的 Hook 点太多，能玩的姿势也太多了。

比如，在 memshell-inject 项目中，我模仿冰蝎的实现方式，hook 了 HttpServletRequest 实现类的 `getQueryString` 方法，在方法返回时修改返回内容进行测试。

正常访问，页面获取当前请求的 QueryString 并打印：

![img](https://oss.javasec.org/images/1623933746321.png)

attach 测试使用的 agent：

![img](https://oss.javasec.org/images/1623933780013.png)

再次访问：

![img](https://oss.javasec.org/images/1623933791544.png)

只能说，将这种功能提供给渗透人员，师傅胆子是真的大，用冰蝎的大多数人还是不清楚原理的，但是小手一点，不知道有授权还是没有的站，JVM 里的字节码就被改了。等各种魔改版冰蝎泛滥后，一些安全防御能力较弱的站将会被 agent 改的体无完肤，再配合加持的持久化技术，不知道会被玩成什么样。

但是既然思路已经开放出来了，攻与防的对抗一定的要有的，作为 RASP 防御方，我一定是要使用魔法来打败魔法，请看下一章的攻防思路及技巧。

补充：顺便看一下同样流行的 webshell 管理工具[哥斯拉](https://github.com/BeichenDream/Godzilla) 的内存马是怎么实现的，截止到文章编写时，发布的 release 版本为 v3.03-godzilla。

可以看到是提供了两种内存马的写入，一种是写入 Servlet，一种是写入 Listener。

![img](https://oss.javasec.org/images/1624411677855.png)

![img](https://oss.javasec.org/images/1624411684573.png)

但是两种写入方式都是针对 Tomcat 的，并不具有通用性，我并没有用过这款工具，只是简单翻了一下代码，没有找到其他发现，如果有，请联系我修改文章。

补充2：再来看下 SpringBoot 持久化 WebShell [ZhouYu](https://github.com/threedr3am/ZhouYu)，在 `zhouyu.core.init.WriteShellTransformer` 中，可以看到是选择了 hook `org.springframework.web.servlet.DispatcherServlet` 的 `doService` 方法。

![img](https://oss.javasec.org/images/1624522943976.png)

此项目中涉及到 jar 包中的 class 替换，以及清空后续的 ClassFileTransformer 的持久化思路。

# 攻防思路及技巧

那么以上就是目前安全行业内主要讨论的内存马添加方式，再加上我找到的一些实现，由于这里主要关注的是内存马的添加，所以关于上下文获取、关键类的定位等技术细节都略过了。

对于一些内存马的实现，由于篇幅的原因，在本篇博客中仅示范了在 Tomcat 下的效果，在[项目代码](https://github.com/su18/MemoryShell)中，还有在研究测试中遇到的其他实现，感兴趣的师傅请 clone 代码仔细观看。

从接下来根据上面的铺垫开始探究查杀的具体思路和实现。正所谓未知攻，焉知防？在这一章节中，重点将讨论对于目前对于内存马的查杀与攻防思路的碰撞。对于各种类型内存马的查杀，各位师傅已经给出了自己的相关思路，我这里根据自己的想法和经验，再结合 RASP 技术的相关实现进行讨论。

## Dynamic Add

动态注册，首先，在 Servlet-API 中我们讨论的对于 Servlet，Filter，Listener 的实现，在理论上 API 中是提供添加接口的，但是在之前的分析中提到过，只有程序初始化时可以用，程序运行时会抛异常，可以通过修改 state 值来进行绕过。

此外，在写入过程中，对于某些中间件自己实现的 Context 对象也提供了添加 Servlet/Filter/Listener 的以及相关 mapping 的方法，以 RASP 的防御思路来说，就是 Hook 这些 add/set 方法，在程序运行中禁止动态添加。

但是这种情况分分钟被绕过，因为在我的示例代码中，有大部分是没有调用这些方法，而是直接将对象写到储存的 maps/lists/arrays 中的，可以绕过添加方法调用的 hook 点。而且，这种 Hook 防御各个中间件的实现也不一样，不能通用，需要适配。

除了 Servlet-API，也可以使用中间件中的一些实现，来完成内存马的写入操作，我这里仅仅在 GlassFish 中找了一点，而实际上还可以被挖掘出很多。

所以，在防御功能的实现中，我们需要重点关注的就是这些具有职责链设计对象实现的**储存和缓存位置**。

## ClassLoader

考虑到内存马通常是配合反序列化等类型的漏洞进行注入，那如果程序里注册的 Servlet/Filter/Listener 是一些高危的 ClassLoader 加载进来的，是不是就说明这个类本身危险很大的？

答案是肯定的，但是同样是可以被绕过的，例如注入 class 到当前线程中，然后实例化注入内存马。

## DumpClass

在 c0ny1 师傅的内存马查杀[项目](https://github.com/c0ny1/java-memshell-scanner)中，使用了 dumpclass 功能，将 filterMaps 中的所有 filterMap 遍历出来，然后提供了 dumpclass，很显然，如果获得目标类的 class 反编译代码，加入人为判断的模式，就可以知道 filter 代码中是否有恶意操作了。在 copagent 中也使用了类似的功能。这种检查思路作为一款查杀工具完全没有问题，但如果作为一款产品来说就有利有弊了。

## Class File

内存马最大的特点就是储存在内存，无文件落地，那也就代表了这个类对应的 ClassLoader 目录下没有对应的 class 文件，这种思路也在 c0ny1 和 jweny 师傅的文章中提到了。

但是这种思路能否被绕过呢？能否让一个无文件落地的内存马在使用其 ClassLoader 的 `getResource` 方法时不返回空呢？答案在 `findResource` 中。

但无论如何这是一个非常好的思路，可以借鉴。

## Mbeans

有师傅提出了利用 VisualVM 来监控 Mbeans 来检测内存马的思路，原理是在注册类似 Filter 的时候会触发 registerJMX 的操作来注册 mbean，不过 mbean 的注册只是为了方便资源的管理，并不影响功能，所以攻击者植入内存 Webshell 之后，完全可以通过执行 Java 代码来卸载掉这个 mbean 来隐藏自己。

以上描述来自长亭 Litch1 师傅的文章，师傅也在他的文章中给出了注销 Tomcat Filter 注册的 mbeans 的代码，可以看出使用这种方式有检测出部分内存马的可能，但是不通用也无法覆盖全面，我这里不会采用这种方式，将不会进行讨论。

## Retransform/Redefine

如何查杀使用 JavaAgent 技术修改字节码的内存马？宽字节安全给出了[相关文章](https://mp.weixin.qq.com/s/Whta6akjaZamc3nOY1Tvxg#at) 进行讨论。

写入 Agent 马后如何不被别人干掉？threedr3am 师傅的[项目](https://github.com/threedr3am/ZhouYu)使用了阻止后续 javaagent 加载的方式，防止webshell 被查杀。

Agent 马的攻防还在进行中，那么对其防御，肯定是要用魔法来打败魔法，这里不废话，请直接看实现。

# 查杀内存马

在这一章节中，将会给出我对于查杀内存马的相关思考，以及我实现的查杀代码的相关测试记录。

## 查找目前服务器上的内存马

结合之前师傅们提出的多个维度的判断方式，配合 JavaAgent 技术来进行内存马的查杀。

## 防御内存马的添加与访问

对应接口 Hook，以监听者模式监控系统关键属性。

## 杀掉目前存在的内存马

对于非Agent马两种思路：

- 从系统中移除该对象。（推荐）
- 访问时抛异常（或跳过调用），中断此次调用。

对于Agent马：retransform。

## 处理想要持久化的内存马

根据网上的一些持久化思路，包括 ServletContainerInitializer/@Filter/@Servlet/addShutdownHook/startUpClass 等等，有针对性的进行查杀和防御。

## 参考

LandGrey 师傅的项目 [copagent](https://github.com/LandGrey/copagent) 使用 javaagent 技术获得了全部的类，判断其包名、实现类名、接口名、注解来提取关键类，并根据类是否在磁盘上有资源链接对象、类中是否包含恶意行为关键字来判断其是否为内存马。

在这里我参考了其项目，在 retransform 时做了同样的事，并在此基础上添加了一定的防御功能：同时 retransform 了恶意类，并在其关键调用代码调用时处理自己的逻辑。

## 视频

以下为测试过程[录屏](https://youtu.be/tTFv15uCNjQ)。

[![Memory Shell Test](https://oss.javasec.org/images/youtube--tTFv15uCNjQ-c05b58ac6eb4c4700831b2b3070cd403.jpg)](https://youtu.be/tTFv15uCNjQ)

# 广告

公开的还是娱乐向的测试代码，能解决问题吗？首先答案是肯定的，能在一定程度上解决问题，我同时也提供了测试代码，欢迎吐槽。但是如果你看完了本篇的文章和代码，你会发现能玩的东西还很多，这个项目主要用于尝试更多的想法和抛砖引玉，所以较为完整和成熟的 JavaWeb 内存马防御能力代码，请关注 RASP 安全产品：[安百科技-灵蜥](http://www.anbai.com/lxPlatform/)。

# 致谢

感谢全体网安从业者的讨论和分享。