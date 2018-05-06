target = ../libFeatureVector.so
src = clusterUsingDomainInfo.cpp \
	DGA_detection.cpp \
	trieTree.cpp
dep = clusterUsingDomainInfo.h \
	DGA_detection.h \
	trieTree.h

$(target): $(src) $(dep)
	g++ -o $(target) -shared -fPIC $(src)

clean:
	rm -rf *.o $(target)