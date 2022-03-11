coord:
	cc -g -o coord coord.c -lm
aggregate6:
	cc -g -o aggregate6 aggregate6.c
aggregate:
	cc -g -o aggregate aggregate.c
aggtest:
	cc -g -o aggtest aggtest.c
clean:
	rm -f aggregate aggtest aggregate6 coord
