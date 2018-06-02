#coding: utf8

try:
	import MySQLdb as pymysql
except ImportError:
	import pymysql 
from apscheduler.schedulers.background import BackgroundScheduler

# MySQL连接对象
# 定义了基本数据库操作
class MySQL(object):
	def __init__(self, host, user, passwd, db, port=3306, charset='utf8'):
		self.host = host
		self.user = user
		self.passwd = passwd
		self.db = db
		self.port = port
		self.charset = charset
		self.connect()
		# self.refresh()

	def get(self, sql):
		self.cursor.execute(sql)
		return self.cursor.fetchone()

	def query(self, sql):
		self.cursor.execute(sql)
		return self.cursor.fetchall()

	def execute(self, sql):
		try:
			self.cursor.execute(sql)
			self.conn.commit()
		except Exception as e:
			self.conn.rollback()

	def connect(self):
		self.conn = pymysql.connect(
						host = self.host, 
						port = self.port, 
						user = self.user,
						passwd = self.passwd,
						db = self.db,
						charset = self.charset
						)
		self.cursor = self.conn.cursor()

	# 每隔28000s，自动刷新连接（针对IPCIS_DNS_DB库）
	def refresh(self):
		s = BackgroundScheduler()
		s.add_job(self.close, 'interval', seconds=28000)
		s.add_job(self.connect, 'interval', seconds=28000)

		s.start()

	def close(self):
		self.cursor.close()
		self.conn.close()