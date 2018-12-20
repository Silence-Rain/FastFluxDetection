target = search
obj = linux_search.o
src = linux_search.cpp

$(target): $(src) $(deps)
	g++ -c $(src)
	g++ -o $(target) $(obj)
	rm -f $(obj)

clean:
	rm -f $(target)
