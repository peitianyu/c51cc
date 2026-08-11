
#ifdef __C251__
/* C251: int = 16 bit, pointer = 16 bit */
int
main()
{
	int x;
	if((sizeof (int) - 2))
		return 1;
	if((sizeof (&x) - 2))
		return 1;
	return 0;
}
#else
int
main()
{
	int x;
	if((sizeof (int) - 4))
		return 1;
	if((sizeof (&x) - 8))
		return 1;
	return 0;
}
#endif
