src = getDGADomianNamesResolvedIP.cpp
target = ../../libPrimaryDomain.so
deps = getDGADomianNamesResolvedIP.h

$(target): $(src) $(deps)
	g++ -o $(target) -shared -fPIC $(src)

clean:
	rm -rf $(target)