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

	# 获取域名TTL
	# 参数：全域名
	# 返回值：TTL值（第一条记录）
	def get_ttl(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT ttl FROM domain_name WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		return int(rs[0])

	# 获取域名whois信息
	# 参数：全域名
	# 返回值：[whois信息]
	def get_whois(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT * FROM domain_whois WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		return list(rs)

	# 获取域名解析IP
	# 参数：全域名
	# 返回值：[解析IP]
	def get_ip(self, domain):
		ret = []
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		if pd == domain:
			sql = ("SELECT a.ip FROM resolved_ip as a INNER JOIN domain_name as b "
			"ON a.domain_id=b.domain_id WHERE b.primary_domain='%s';" % pd)
		else:
			sql = "SELECT ip FROM resolved_ip WHERE domain_name='%s" % domain
		rs = self.dns.query(sql)
		for item in rs:
			ret.append(int(item[0]))

		return ret

	# 获取域名解析IP地理位置
	# 参数：[解析IP（前1k个）]
	# 返回值：{ip:(lng, lat)...}
	def get_ip_location(self, ips):
		ret = {}
		for ip in ips[:1000]:
			sql = "SELECT longitude,latitude FROM IP2Location WHERE ipStart<%s AND ipEnd>%s;" % (ip, ip)
			rs = self.ipcis.get(sql)
			ret[ip] = rs

		return ret
