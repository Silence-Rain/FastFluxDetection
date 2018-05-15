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

	# 初始化C++动态库接口
	def initCppLib(self):
		ll = cdll.LoadLibrary
		lib = ll("lib/libPrimaryDomain.so")
		init = lib.init
		self.getPrimaryDomain = lib.getPrimaryDomain
		self.getPrimaryDomain.argtypes = [c_char_p]
		self.getPrimaryDomain.restype = c_char_p

		init()

	# 获取域名TTL
	# 参数：全域名
	# 返回值：TTL值（第一条记录）
	async def get_ttl(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT ttl FROM domain_name WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		return int(rs[0])

	# 获取域名whois信息
	# 参数：全域名
	# 返回值：[whois信息]
	async def get_whois(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT * FROM domain_whois WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		return list(rs)

	# 获取域名解析IP
	# 参数：全域名
	# 返回值：[解析IP]
	async def get_ip(self, domain):
		sql = "SELECT ip FROM resolved_ip WHERE domain_name='%s" % domain
		rs = self.dns.query(sql)
		ret = []
		for item in rs:
			ret.append(int(item[0]))

		return ret

	# 获取域名解析IP地理位置
	# 参数：[解析IP]
	# 返回值：{ip:(lng, lat)...}
	async def get_ip_location(self, ips):
		ret = {}
		for ip in ips:
			sql = "SELECT longitude,latitude FROM IP2Location WHERE ipStart<%s AND ipEnd>%s;" % ip
			rs = self.ipcis.get(sql)
			ret[ip] = rs

		return ret
