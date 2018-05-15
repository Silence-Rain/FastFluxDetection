#!coding=utf8

from mysql import MySQL
from ctypes import *
from config import *

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

	def initCppLib(self):
		ll = cdll.LoadLibrary
		lib = ll("lib/libPrimaryDomain.so")
		init = lib.init
		self.getPrimaryDomain = lib.getPrimaryDomain
		self.getPrimaryDomain.argtypes = [c_char_p]
		self.getPrimaryDomain.restype = c_char_p

		init()

	async def get_ttl(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT ttl FROM domain_name WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		return int(rs[0])

	async def get_whois(self, domain):
		pd = self.getPrimaryDomain(domain.encode("utf-8")).decode()
		sql = "SELECT * FROM domain_whois WHERE primary_domain='%s';" % pd
		rs = self.dns.get(sql)

		return list(rs[0])

	async def get_ip(self, domain):
		sql = "SELECT ip FROM resolved_ip WHERE domain_name='%s" % domain
		rs = self.dns.query(sql)
		ret = []
		for item in rs:
			ret.append(int(item[0]))

		return ret

	async def get_ip_location(self, ips):
		ret = {}
		for ip in ips:
			sql = "SELECT longitude,latitude FROM IP2Location WHERE ipStart<%s AND ipEnd>%s;" % ip
			rs = self.ipcis.get(sql)
			ret[ip] = rs

		return ret
