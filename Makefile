cc=g++ 
exe=Fast_Flux_detection
obj=getDGADomianNamesResolvedIP.o 

$(exe):$(obj)
	   $(cc) -o $(exe) $(obj)  -L/usr/lib64/mysql -l mysqlclient
getDGADomianNamesResolvedIP.o:getDGADomianNamesResolvedIP.cpp
		$(cc) -g -c getDGADomianNamesResolvedIP.cpp -I/usr/include/mysql

clean:
	rm -rf *.o Fast_Flux_detection
