src = getDGADomianNamesResolvedIP.cpp
target = ../libPrimaryDomain.so
deps = getDGADomianNamesResolvedIP.h

$(target): $(src) $(deps)
	g++ -o $(target) -shared -fPIC $(src) \
	-I/usr/local/mysql/include/mysql -L/usr/local/mysql/lib -l mysqlclient

clean:
	rm -rf *.so