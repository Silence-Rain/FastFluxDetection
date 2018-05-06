target = ../libFeatureVector.so
src = clusterUsingDomainInfo.cpp \
	DGA_detection.cpp \
	trieTree.cpp \

$(target): $(src)
	g++ -o $(target) -shared -fPIC $(src)

clean:
	rm -rf *.o