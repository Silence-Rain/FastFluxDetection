#coding: utf8

try:
	import MySQLdb
except ImportError:
	import pymysql as MySQLdb

# MySQL连接对象
# 定义了基本数据库操作
class MySQL(object):
	def __init__(self, host, user, passwd, db, port=3306, charset='utf8'):
		self.conn = MySQLdb.connect(
						host = host, 
						port = port, 
						user = user,
						passwd = passwd,
						db = db,
						charset = charset
						)
		self.cursor = self.conn.cursor()

	# 查询一条记录
	def get(self, sql):
		self.cursor.execute(sql)
		return self.cursor.fetchone()

	# 查询所有记录
	def query(self, sql):
		self.cursor.execute(sql)
		return self.cursor.fetchall()

	# 无返回值的执行语句
	def execute(self, sql):
		try:
			self.cursor.execute(sql)
			self.conn.commit()
		except Exception as e:
			self.conn.rollback()

	def close(self):
		self.cursor.close()
		self.conn.close()