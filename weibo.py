#! /usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
import urllib2
import cookielib
import base64
import re
import json
import hashlib
import rsa
import binascii



def get_servertime(username):
	url = 'http://login.sina.com.cn/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=%s&rsakt=mod&client=ssologin.js(v1.4.18)' % username
	data = urllib2.urlopen(url).read()
	p = re.compile('\((.*)\)')
	try:
		json_data = p.search(data).group(1)
		data = json.loads(json_data)
		servertime = str(data['servertime'])
		nonce = data['nonce']
		pubkey = data['pubkey']
		rsakv = data['rsakv']
		return servertime, nonce, pubkey, rsakv
	except:
		print 'Get severtime error!'
		return None

def get_pwd(password, servertime, nonce, pubkey):
	rsaPublickey = int(pubkey, 16)
	key = rsa.PublicKey(rsaPublickey, 65537) #创建公钥
	message = str(servertime) + '\t' + str(nonce) + '\n' + str(password) #拼接明文js加密文件中得到
	passwd = rsa.encrypt(message, key) #加密
	passwd = binascii.b2a_hex(passwd) #将加密信息转换为16进制。
	return passwd

def get_user(username):
	username_ = urllib.quote(username)
	username = base64.encodestring(username_)[:-1]
	return username

	
def login():
	postdata = {
		'entry': 'weibo',
		'gateway': '1',
		'from': '',
		'savestate': '30',
		'userticket': '0',
		'vsnf': '1',
		'su': '',
		'service': 'sso',
		'servertime': '',
		'nonce': '',
		'pwencode': 'rsa2',
		'sp': '',
		'encoding': 'UTF-8',
		'cdult':'2',
		'domain':'weibo.com',
		'prelt':'565',
		'returntype':'TEXT',
		'pagerefer': 'http://s.weibo.com/user/%25E7%2599%25BE%25E5%25BA%25A6&Refer=index',
	}

	username = 'kczsxylr@163.com'
	pwd = '19920724kc'

	url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
	try:
		servertime, nonce, pubkey, rsakv = get_servertime(username)
		print servertime
		print nonce
		print pubkey
		print rsakv
	except:
		print 'get servertime error!'
		return
	postdata['servertime'] = servertime
	postdata['nonce'] = nonce
	postdata['rsakv'] = rsakv
	postdata['su'] = get_user(username)
	postdata['sp'] = get_pwd(pwd, servertime, nonce, pubkey)
	print postdata
	postdata = urllib.urlencode(postdata)
	headers = {'User-Agent':'Mozilla/5.0 (X11; Linux i686; rv:8.0) Gecko/20100101 Firefox/8.0 Chrome/20.0.1132.57 Safari/536.11'}
	req  = urllib2.Request(
		url = url,
		data = postdata,
		headers = headers
	)
	result = urllib2.urlopen(req)
	text = result.read()
	print text
	print cj
	p = re.compile('location\.replace\(\"(.*)\"\)')#此处和之前略有区别，小心！
	xxx = urllib2.urlopen('http://www.weibo.com/u/3103746290/home').read()
	fp = open('xx.txt','w')
	fp.write(xxx)
	fp.close()
	try:
		login_url = re.findall("location.replace\(\'(.*?)\'\);" , text)[0]
		print login_url
		urllib2.urlopen(login_url)
		print "Login success!"
		return 1
	except:
		print 'Login error!'
		return 0
		

cj = cookielib.LWPCookieJar()
cookie_support = urllib2.HTTPCookieProcessor(cj)
opener = urllib2.build_opener(cookie_support, urllib2.HTTPHandler)
urllib2.install_opener(opener)

login()
