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
	@Value("${USER_SESSION}")
	private String USER_SESSION;
	@Value("${EXPIRE_TIME}")
	private Integer EXPIRE_TIME;
	
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
	
	@Override
	public CzolResult register(CzUser user) {
		//注册之前还得进行检查防止出现重复情况
		if(StringUtils.isBlank(user.getuName())){
			return CzolResult.build(400, "用户名不能为空");
		}
		CzolResult czolResult = this.checkData(user.getuName(), 1);
		if(!(boolean) czolResult.getData()){
			return CzolResult.build(400, "用户名不能重复");
		}
		if(StringUtils.isBlank(user.getuPassword())){
			return CzolResult.build(400, "密码不能为空");
		}
		if(StringUtils.isNotBlank(user.getuEmail())){
			czolResult = this.checkData(user.getuEmail(), 2);
			if(!(boolean) czolResult.getData()){
				return CzolResult.build(400, "邮箱重复");
			}
		}
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
		String jsonUser=JsonUtils.objectToJson(user);
		String token=UUID.randomUUID().toString().replace("-", "");
		jedisClient.set(USER_SESSION+":"+token, jsonUser);
		jedisClient.expire(USER_SESSION+":"+token,EXPIRE_TIME);
		return CzolResult.ok(token);
	}

	@Override
	public CzolResult getUserByToken(String token) {
		if(StringUtils.isBlank(token)){
			return CzolResult.build(400, "token不能为空");
		}
		String string = jedisClient.get(USER_SESSION + ":"+token);
		if(StringUtils.isBlank(string)){
			return CzolResult.build(400, "用户信息已过期，请重新登录");
		}
		jedisClient.expire(USER_SESSION + ":"+token, EXPIRE_TIME);
		CzUser user = JsonUtils.jsonToPojo(string, CzUser.class);
		return CzolResult.ok(user);
	}

	@Override
	public CzolResult logout(String token) {
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
