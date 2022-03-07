aggregate:
	cc -g -o aggregate aggregate.c
aggtest:
	cc -g -o aggtest aggtest.c
clean:
	rm -f aggregate aggtest
