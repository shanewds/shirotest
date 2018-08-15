package com.shirotest;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.config.IniSecurityManagerFactory;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.apache.shiro.crypto.hash.DefaultHashService;
import org.apache.shiro.crypto.hash.HashRequest;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.util.ByteSource;
import org.apache.shiro.util.Factory;
import org.apache.shiro.util.SimpleByteSource;
import org.junit.Test;



public class RoleTest extends BaseTest {

   
	@Test
    public void test() {
		
		DefaultHashService hashService = new DefaultHashService(); //默认算法SHA-512
		hashService.setHashAlgorithmName("SHA-512");
		hashService.setPrivateSalt(new SimpleByteSource("123")); //私盐，默认无
		hashService.setGeneratePublicSalt(true);//是否生成公盐，默认false
		hashService.setRandomNumberGenerator(new SecureRandomNumberGenerator());//用于生成公盐。默认就这个
		hashService.setHashIterations(1); //生成Hash值的迭代次数
		HashRequest request = new HashRequest.Builder()
		            .setAlgorithmName("MD5").setSource(ByteSource.Util.bytes("hello"))
		            .setSalt(ByteSource.Util.bytes("123")).setIterations(2).build();
		String hex = hashService.computeHash(request).toHex();
	    System.out.println(hex);
		
	}
	
	
	
	
	
	@Test
    public void testCustomRealm() {
		login("classpath:shiro-role.ini", "li", "123");
        //断言拥有权限：user:create
        subject().checkPermission("user:create");
        subject().isPermitted("user:create");
        //断言拥有权限：user:delete and user:update
        subject().checkPermissions("user222:view");
        //断言拥有权限：user:view 失败抛出异常
      

    }

	private void login(String configFile) {
        //1、获取SecurityManager工厂，此处使用Ini配置文件初始化SecurityManager
        Factory<org.apache.shiro.mgt.SecurityManager> factory =
                new IniSecurityManagerFactory(configFile);

        //2、得到SecurityManager实例 并绑定给SecurityUtils
        org.apache.shiro.mgt.SecurityManager securityManager = factory.getInstance();
        SecurityUtils.setSecurityManager(securityManager);

        //3、得到Subject及创建用户名/密码身份验证Token（即用户身份/凭证）
        Subject subject = SecurityUtils.getSubject();
        UsernamePasswordToken token = new UsernamePasswordToken("zhang", "123");

        subject.login(token);
    }

	
	
	
}
