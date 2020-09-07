package com.nsapi.niceschoolapi.common.config;

import at.pollux.thymeleaf.shiro.dialect.ShiroDialect;
import com.nsapi.niceschoolapi.common.realm.AuthRealm;
import org.apache.shiro.cache.ehcache.EhCacheManager;
import org.apache.shiro.codec.Base64;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.filter.authc.FormAuthenticationFilter;
import org.apache.shiro.web.mgt.CookieRememberMeManager;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.apache.shiro.web.servlet.SimpleCookie;
import org.apache.shiro.web.session.mgt.DefaultWebSessionManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.context.annotation.Bean;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@SpringBootConfiguration
public class ShiroConfig {

    private Logger logger = LoggerFactory.getLogger(ShiroConfig.class);

    @Bean(name = "shiroFilter")
    public ShiroFilterFactoryBean shiroFilterFactoryBean(@Qualifier("authRealm")AuthRealm authRealm){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        bean.setSecurityManager(securityManager(authRealm));
        bean.setSuccessUrl("/index");
        //登录成功
        bean.setSuccessUrl("/home");
        //登录失败
        bean.setLoginUrl("/home");
        Map<String,Filter> map = new HashMap();
        //表示所有的 authc都要校验
        map.put("authc",new FormAuthenticationFilter());
        bean.setFilters(map);

        //当运行一个Web应用程序时,Shiro将会创建一些有用的默认Filter实例,并自动地在[main]项中将它们置为可用自动地可用的默认的Filter实例是被
        // DefaultFilter枚举类定义的,枚举的名称字段就是可供配置的名称
        /**
         * anon---------------org.apache.shiro.web.filter.authc.AnonymousFilter 没有参数，表示可以匿名使用。
         * authc--------------org.apache.shiro.web.filter.authc.FormAuthenticationFilter 表示需要认证(登录)才能使用，没有参数
         * authcBasic---------org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter 没有参数表示httpBasic认证
         * logout-------------org.apache.shiro.web.filter.authc.LogoutFilter
         * noSessionCreation--org.apache.shiro.web.filter.session.NoSessionCreationFilter
         * perms--------------org.apache.shiro.web.filter.authz.PermissionAuthorizationFilter 参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，例如/admins/user/**=perms["user:add:*,user:modify:*"]，当有多个参数时必须每个参数都通过才通过，想当于isPermitedAll()方法。
         * port---------------org.apache.shiro.web.filter.authz.PortFilter port[8081],当请求的url的端口不是8081是跳转到schemal://serverName:8081?queryString,其中schmal是协议http或https等，serverName是你访问的host,8081是url配置里port的端口，queryString是你访问的url里的？后面的参数。
         * rest---------------org.apache.shiro.web.filter.authz.HttpMethodPermissionFilter 根据请求的方法，相当于/admins/user/**=perms[user:method] ,其中method为post，get，delete等。
         * roles--------------org.apache.shiro.web.filter.authz.RolesAuthorizationFilter 参数可以写多个，多个时必须加上引号，并且参数之间用逗号分割，当有多个参数时，例如admins/user/**=roles["admin,guest"],每个参数通过才算通过，相当于hasAllRoles()方法。
         * ssl----------------org.apache.shiro.web.filter.authz.SslFilter 没有参数，表示安全的url请求，协议为https
         * user---------------org.apache.shiro.web.filter.authz.UserFilter 没有参数表示必须存在用户，当登入操作时不做检查
         */


        //配置访问权限
        LinkedHashMap<String, String> filterChainDefinitionMap = new LinkedHashMap();
        // anon 表示不会被拦截的 url,即无需认证
        filterChainDefinitionMap.put("/","anon");
        filterChainDefinitionMap.put("/static/**","anon");
        filterChainDefinitionMap.put("/admin","anon");
        filterChainDefinitionMap.put("/home","anon");
        filterChainDefinitionMap.put("/newslist","anon");
        filterChainDefinitionMap.put("/admin/system/user/changePassword","anon");//修改密码
        filterChainDefinitionMap.put("/admin/system/user/add","anon");//注册
        filterChainDefinitionMap.put("/appraise/seltch","anon");
        filterChainDefinitionMap.put("/schedulelist","anon");
        filterChainDefinitionMap.put("/admin/index","anon");
        filterChainDefinitionMap.put("/admin/login","anon");
        filterChainDefinitionMap.put("/toLogin","anon");
        filterChainDefinitionMap.put("/getCaptcha","anon");
        filterChainDefinitionMap.put("/anonCtrl/","anon");
        filterChainDefinitionMap.put("/sysRole/test","anon");
        // /** 应该已经包括这个url了吧
        filterChainDefinitionMap.put("/systemLogout","authc");
        //所有请求需要oauth2认证
        filterChainDefinitionMap.put("/**","authc");
        bean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        return bean;
    }

    @Bean
    public SecurityManager securityManager(@Qualifier("authRealm")AuthRealm authRealm){
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(authRealm);
        defaultWebSecurityManager.setRememberMeManager(rememberMeManager());
        defaultWebSecurityManager.setSessionManager(webSessionManager());
        defaultWebSecurityManager.setCacheManager(cacheManager());
        return defaultWebSecurityManager;
    }


    /**
     * shiro缓存管理器;
     * 需要注入安全管理器：securityManager
     */
    @Bean
    public EhCacheManager cacheManager(){
        EhCacheManager cacheManager = new EhCacheManager();
        cacheManager.setCacheManagerConfigFile("classpath:ehcache-shiro.xml");
        return cacheManager;
    }


    @Bean
    public CookieRememberMeManager rememberMeManager(){
        CookieRememberMeManager rememberMeManager = new CookieRememberMeManager();
        rememberMeManager.setCookie(rememberMeCookie());
        rememberMeManager.setCipherKey(Base64.decode("2AvVhdsgUs0FSA3SDFAdag=="));
        return rememberMeManager;
    }

    @Bean
    public SimpleCookie rememberMeCookie(){
        //这个参数是cookie的名称，对应前端的checkbox的name = rememberMe
        SimpleCookie cookie = new SimpleCookie("rememberMe");
        cookie.setHttpOnly(true);
        //记住我有效期长达一周
        cookie.setMaxAge(604800);
        return cookie;
    }

    @Bean
    public SessionManager webSessionManager(){
        DefaultWebSessionManager manager = new DefaultWebSessionManager();
        //设置session过期时间为1小时(单位：毫秒)，默认为30分钟
        manager.setGlobalSessionTimeout(60 * 60 * 1000);
        manager.setSessionValidationSchedulerEnabled(true);
        //manager.setSessionDAO(redisSessionDAO());
        return manager;
    }

    /**
     * AOP式方法级权限检查
     * @return
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){
        DefaultAdvisorAutoProxyCreator creator = new DefaultAdvisorAutoProxyCreator();
        creator.setProxyTargetClass(true);
        return creator;
    }

    /**
     *  保证实现了Shiro内部lifecycle函数的bean执行
     * @return
     */
    @Bean
    public static LifecycleBeanPostProcessor lifecycleBeanPostProcessor(){
        return new LifecycleBeanPostProcessor();
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(@Qualifier("authRealm")AuthRealm authRealm) {
        SecurityManager manager = securityManager(authRealm);
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(manager);
        return advisor;
    }

    @Bean
    public ShiroDialect shiroDialect() {
        return new ShiroDialect();
    }


}
