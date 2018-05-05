cc=g++
exe=DGA_detection
obj=DGA_detection.o \
    clusterUsingDomainInfo.o \
	trieTree.o
$(exe):$(obj)
	   $(cc) -o $(exe) $(obj)
DGA_detection.o:DGA_detection.cpp
		$(cc) -g -c DGA_detection.cpp
clusterUsingDomainInfo.o:clusterUsingDomainInfo.cpp
		$(cc) -g -c clusterUsingDomainInfo.cpp
trieTree.o:trieTree.cpp
		$(cc) -g -c trieTree.cpp
clean:
	rm -rf *.o DGA_detection
