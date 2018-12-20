import io
import re

def read_dict(path):
	with io.open(path, "r", encoding="utf8") as f:
		return eval(f.read())

def read_file(path):
	ret = []

	with io.open(path, "r", encoding="utf8") as f:
		for line in f.readlines():
			rs = re.search(r"(.+)(\[.+\])(.+)\:(.+)", line)

			domain = rs.group(1)
			ips = eval(rs.group(2))
			times = rs.group(3).split(",")
			ttl = int(times[0])
			expire = int(times[3])
			nss = rs.group(4).split(",")

			ret.append({domain: {"iplist": ips, "nslist": nss, "ttl": ttl, "whois_expire": expire}})

	return ret


if __name__ == '__main__':
	raw = read_file("./temp/data")
	ns_dict = read_dict("./temp/ns.tmp")
	resolved_dict = read_dict("./temp/resolved.tmp")