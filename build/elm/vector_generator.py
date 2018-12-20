import io

with io.open("./temp/ns.tmp", "r", encoding="utf8") as f:
	ns_dict = eval(f.read())

	print(ns_dict["220.194.200.70"])
