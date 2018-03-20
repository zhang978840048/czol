package com.czol.sso.service.impl;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.util.DigestUtils;

import com.czol.mapper.CzUserMapper;
import com.czol.pojo.CzUser;
import com.czol.pojo.CzUserExample;
import com.czol.pojo.CzUserExample.Criteria;
import com.czol.pojo.CzolResult;
import com.czol.sso.redis.JedisClient;
import com.czol.sso.redis.JedisClientPool;
import com.czol.sso.service.SsoService;
import com.czol.utils.JsonUtils;
@Service
public class SsoServiceImpl implements SsoService{
	@Autowired
	private CzUserMapper czUserMapper;
	@Autowired
	private JedisClient jedisClient;
	//redis缓存中添加用户信息的的Key设置
	@Value("${USER_SESSION}")
	private String USER_SESSION;
	//redis中设置用户信息的过期时间
	@Value("${EXPIRE_TIME}")
	private Integer EXPIRE_TIME;
	
	//检查数据，可通用，比如前台发送ajax检查以及后面注册前的检查
	@Override
	public CzolResult checkData(String param,Integer type){
		CzUserExample example=new CzUserExample();
		Criteria criteria = example.createCriteria();
		//1是检查用户名用户名 2是检查邮箱 3是检查电话号码
		if(type==1){
			criteria.andUNameEqualTo(param);
		}else if( type==2){
			criteria.andUEmailEqualTo(param);
		}else if(type==3){
			criteria.andUTelephoneEqualTo(param);
		}else{
			return CzolResult.build(400, "参数中包含非法数据");
		}
		List<CzUser> list = czUserMapper.selectByExample(example);
		if(list.size()>0&& list!=null){
			return CzolResult.build(400, "参数错误");
		}
		return CzolResult.ok(true);
	}
	
	//用户注册
	@Override
	public CzolResult register(CzUser user) {
		//注册之前还得进行检查防止出现重复情况
		//判断用户名是否为空及重复
		if(StringUtils.isBlank(user.getuName())){
			return CzolResult.build(400, "用户名不能为空");
		}
		CzolResult czolResult = this.checkData(user.getuName(), 1);
		if(!(boolean) czolResult.getData()){
			return CzolResult.build(400, "用户名不能重复");
		}
		//检查密码是否为空
		if(StringUtils.isBlank(user.getuPassword())){
			return CzolResult.build(400, "密码不能为空");
		}
		//检查邮箱是否为空并重复
		if(StringUtils.isNotBlank(user.getuEmail())){
			czolResult = this.checkData(user.getuEmail(), 2);
			if(!(boolean) czolResult.getData()){
				return CzolResult.build(400, "邮箱重复");
			}
		}
		//检查电话是否为空并重复
		if(StringUtils.isNotBlank(user.getuTelephone())){
			czolResult = this.checkData(user.getuTelephone(), 3);
			if(!(boolean) czolResult.getData()){
				return CzolResult.build(400, "电话重复");
			}
		}
		//补全User属性
		user.setuCreatedate(new Date());
		user.setuUpdatedate(new Date());
		//将密码进行md5加密放入User中
		String pwd=DigestUtils.md5DigestAsHex(user.getuPassword().getBytes()).toString();
		user.setuPassword(pwd);
		//向数据库中插入User
		czUserMapper.insert(user);
		return CzolResult.ok();
	}
	
	//用户登录
	@Override
	public CzolResult login(String username, String password) {
		//去除username与数据库中比较
		CzUserExample example=new CzUserExample();
		Criteria criteria = example.createCriteria();
		//判断用户名是否为空 
		if(StringUtils.isBlank(username)){
			return CzolResult.build(400, "用户名不能为空");
		}
		//从数据库中判断该用户是否存在
		criteria.andUNameEqualTo(username);
		List<CzUser> list = czUserMapper.selectByExample(example);
		if(list==null||list.size()<0){
			return CzolResult.build(400, "该用户名不存在");
		}
		//存在的话取出该用户，并继续判断密码是否正确
		CzUser user=list.get(0);
		String pwd = DigestUtils.md5DigestAsHex(password.getBytes()).toString();
		if(!pwd.equals(user.getuPassword())){
			return CzolResult.build(400, "用户名或密码错误");
		}
		//将密码设成null，并将用户信息放入Redis缓存中
		user.setuPassword(null);
		//使用json工具将user转换为json对象
		String jsonUser=JsonUtils.objectToJson(user);
		//取UUID作为Token
		String token=UUID.randomUUID().toString().replace("-", "");
		//向Redis中设置用户信息
		jedisClient.set(USER_SESSION+":"+token, jsonUser);
		//设置用户信息过期时间
		jedisClient.expire(USER_SESSION+":"+token,EXPIRE_TIME);
		//返回token对象，将向Cookie中写入
		return CzolResult.ok(token);
	}
	
	//使用Token在redis查询用户信息
	@Override
	public CzolResult getUserByToken(String token) {
		//判断Token是否为空
		if(StringUtils.isBlank(token)){
			return CzolResult.build(400, "token不能为空");
		}
		//从Redis中获取用户信息
		String string = jedisClient.get(USER_SESSION + ":"+token);
		//判断用户信息是否为空，假如为空则用户信息已过期，没过期取出并重新设置过期时间
		if(StringUtils.isBlank(string)){
			return CzolResult.build(400, "用户信息已过期，请重新登录");
		}
		jedisClient.expire(USER_SESSION + ":"+token, EXPIRE_TIME);
		//使用json工具将json转换为Czuser对象并返回
		CzUser user = JsonUtils.jsonToPojo(string, CzUser.class);
		return CzolResult.ok(user);
	}

	//用户退出
	@Override
	public CzolResult logout(String token) {
		//判断token是否为空，不为空则将对应得value干掉
		if(StringUtils.isBlank(token)){
			return CzolResult.build(400, "token不能为空");
		}
		Long del = jedisClient.del(USER_SESSION+":"+token);
		if(del!=null || !(del.longValue()==0)){
			return CzolResult.build(400, "退出失败");
		}
		return CzolResult.ok();
	}
		
	
}
