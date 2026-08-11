
#ifdef __C251__
/* C251: int = 16 bit, long long not supported */
int
main()
{
	int x;
	x = 0;
	x = ~x;
	if (x != 0xffff)
		return 1;
	return 0;
}
#else
int
main()
{
	int x;
	long long l;

	x = 0;
	l = 0;

	x = ~x;
	if (x != 0xffffffff)
		return 1;

	l = ~l;
	if (x != 0xffffffffffffffff)
		return 2;

	return 0;
}
#endif
