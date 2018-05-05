src = getDGADomianNamesResolvedIP.cpp
target = ../libPrimaryDomain.so

$(target): $(src)
	g++ -o $(target) -shared -fPIC $(src) \
	-I/usr/local/mysql/include/mysql -L/usr/local/mysql/lib -l mysqlclient

clean:
	rm -rf *.so