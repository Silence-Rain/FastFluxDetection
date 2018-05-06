target = test1
obj = clusterUsingDomainInfo.o \
	DGA_detection.o \
	trieTree.o

$(target): $(obj)
	g++ -o $(target) $(obj)
clusterUsingDomainInfo.o: clusterUsingDomainInfo.cpp
	g++ -g -c clusterUsingDomainInfo.cpp
DGA_detection.o: DGA_detection.cpp
	g++ -g -c DGA_detection.cpp
trieTree.o: trieTree.cpp
	g++ -g -c trieTree.cpp

# target = ../libFeatureVector.so
# src = clusterUsingDomainInfo.cpp

# $(target): $(src)
# 	g++ -o $(target) -shared -fPIC $(src)

clean:
	rm -rf *.o test1