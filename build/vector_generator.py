import io
import re
import IPy
import tools

def read_dict(path):
	with io.open(path, "r", encoding="utf8") as f:
		return eval(f.read())

def read_file(path):
	ret = {}

	with io.open(path, "r", encoding="utf8") as f:
		for line in f.readlines():
			rs = re.search(r"(.+)(\[.+\])(.+)\:(.+)", line)

			domain = rs.group(1)
			ips = eval(rs.group(2))
			times = rs.group(3).split(",")
			ttl = int(times[0])
			expire = int(times[3])
			nss = rs.group(4).split(",")

			ret[domain] = {"iplist": ips, "nslist": nss, "ttl": ttl, "whois_expire": expire}

	return ret

def merge(raw, ns_dict, resolved_dict):
	for k in raw.keys():
		ips = raw[k]["iplist"]
		nss = raw[k]["nslist"]
		ip_locations = []
		ns_locations = []

		for i in ips:
			item = str(IPy.IP(i))
			temp = {}

			temp["location"] = "%s-%s" % (resolved_dict[item]["country"], resolved_dict[item]["region"])
			lng = resolved_dict[item]["longitude"]
			lat = resolved_dict[item]["latitude"]
			temp["lng"] = float(lng.split(" ")[1]) if lng[0] == "东" else -float(lng.split(" ")[1])
			temp["lat"] = float(lat.split(" ")[1]) if lng[0] == "北" else -float(lat.split(" ")[1])

			ip_locations.append(temp)

		for i in nss:
			item = str(IPy.IP(i))
			temp = {}

			lng = ns_dict[item]["longitude"]
			lat = ns_dict[item]["latitude"]
			temp["lng"] = float(lng.split(" ")[1]) if lng[0] == "东" else -float(lng.split(" ")[1])
			temp["lat"] = float(lat.split(" ")[1]) if lng[0] == "北" else -float(lat.split(" ")[1])

			ns_locations.append(temp)

		raw[k]["ip_loc"] = ip_locations
		raw[k]["ns_loc"] = ns_locations

	return raw

def gen_vector(res):
	vectors = {}
	for k, v in res.items():
		ttl = v["ttl"]
		is_expire = tools.whois_expire(v["whois_expire"])
		ip_entropy = tools.shannon_entropy([x["location"] for x in v["ip_loc"]])
		avr_dist = tools.average_distance([[x["lng"], x["lat"]] for x in v["ip_loc"]],
								[[x["lng"], x["lat"]] for x in v["ns_loc"]])

		vectors[k] = [ttl, is_expire, ip_entropy, avr_dist]

	return vectors

def write_file(path, vectors):
	with io.open(path, "w", encoding="utf8") as f:
		for k, v in vectors.items():
			res = [k]
			res.extend(v)
			f.write("%s\n" % str(res))


if __name__ == '__main__':
	raw = read_file("./temp/alexa.dat")
	ns_dict = read_dict("./temp/ns.dict")
	resolved_dict = read_dict("./temp/resolved.dict")
	res = merge(raw, ns_dict, resolved_dict)
	vs = gen_vector(res)
	write_file("./temp/alexa.vec", vs)

