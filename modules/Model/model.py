#!coding=utf8

from mysql import MySQL
from ctypes import *
from config import *

# 获取域名测度信息的model
class DetailModel(object):
	def __init__(self):
		self.ipcis = MySQL(
			host=IPCIS_HOST,
			user=IPCIS_USER,
			passwd=IPCIS_PASSWD,
			db=IPCIS_DB
			)
		self.dns = MySQL(
			host=DNS_HOST,
			user=DNS_USER,
			passwd=DNS_PASSWD,
			port=DNS_PORT,
			db=DNS_DB
			)
		self.initCppLib()

	# 初始化C++动态库接口
	def initCppLib(self):
		ll = cdll.LoadLibrary
		lib = ll("../../lib/libPrimaryDomain.so")
		init = lib.init
		self.getPrimaryDomain = lib.getPrimaryDomain
		self.getPrimaryDomain.argtypes = [c_char_p]
		self.getPrimaryDomain.restype = c_char_p
		init()

	# 获取域名whois信息
	# 参数：全域名
	# 返回值：[whois信息]
	def get_whois(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT * FROM domain_whois WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		if rs != None:
			return list(rs)
		else:
			return []

	# 获取域名解析IP地理位置
	# 参数：[解析IP（前100个）]
	# 返回值：{ip:(国家,地区,城市)...}
	def get_ip_location(self, ips):
		# ret = {}
		# for ip in ips[:100]:
		# 	sql = "SELECT country,region,city FROM IP2Location WHERE ipStart<%s AND ipEnd>%s;" % (ip, ip)
		# 	rs = self.ipcis.get(sql)
		# 	ret[ip] = rs

		# return ret

		proxy = {"http": "http://yunyang:yangyun123@202.112.23.167:8080"}
		cur_date = time.strftime("%Y-%m-%d", time.localtime())
		ret = {}
		for ip in ips[:100]:
			ip_str = str(IPy.IP(ip))
			# 查询当天的IP活动流记录
			r = requests.get("http://211.65.197.210:8080/IPCIS/activityDatabase/"
				"?IpSets=%s:32&TableName=%s&Mode=1" % (ip_str, cur_date), proxies=proxy)
			res = r.json()[ip_str+":32"]
			for i in res:
				# 获得对端IP地理位置
				for item in i[1:]:
					ret.append({ip, item.split("$")[-2].split("-")})

		return ret


	# 获取域名解析IP经纬度
	# 参数：[解析IP（前100个）]
	# 返回值：{self:(经度,纬度), opposite:[(经度,纬度),...]}
	def get_ip_lnglat(self, ips):
		proxy = {"http": "http://yunyang:yangyun123@202.112.23.167:8080"}
		cur_date = time.strftime("%Y-%m-%d", time.localtime())
		ret = {}
		for ip in ips[:100]:
			target_pos = []
			opposite_pos = []
			ip_str = str(IPy.IP(ip))
			# 查询当天的IP活动流记录
			r = requests.get("http://211.65.197.210:8080/IPCIS/activityDatabase/"
				"?IpSets=%s:32&TableName=%s&Mode=1" % (ip_str, cur_date), proxies=proxy)
			res = r.json()[ip_str+":32"]
			for i in res:
				# 获得解析IP经纬度
				target_pos = i[0].split(" ")[-2:] if len(i) != 0 else target_pos
				ret["self"] = target_pos
				# 获得对端IP经纬度
				for item in i[1:]:
					opposite_pos.append(item.split(" ")[-2:])
				ret["opposite"] = opposite_pos

		return ret
