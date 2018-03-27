# cc=g++ 
# exe=Fast_Flux_detection
# obj=getDGADomianNamesResolvedIP.o 

# $(exe):$(obj)
# 	   $(cc) -o $(exe) $(obj)  -L/usr/local/mysql/lib -l mysqlclient
# getDGADomianNamesResolvedIP.o:getDGADomianNamesResolvedIP.cpp
# 		$(cc) -g -c getDGADomianNamesResolvedIP.cpp -I/usr/local/mysql/include/mysql

# clean:
# 	rm -rf *.o Fast_Flux_detection

src = getDGADomianNamesResolvedIP.cpp
target = libPrimaryDomain.so

$(target): $(src)
	g++ -o $(target) -shared -fPIC $(src) \
	-I/usr/local/mysql/include/mysql -L/usr/local/mysql/lib -l mysqlclient

clean:
	rm -rf *.so