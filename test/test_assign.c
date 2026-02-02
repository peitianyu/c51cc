
/*
 * 复合赋值运算符测试：
 *   <<= >>= &= |= ^= += -= *= /= %=
 *
 * 该文件用于喂给 parser/ssa 的输入，不依赖标准库。
 */

int g = 3;
int h = 5;

struct S {
	int x;
	int y;
	unsigned int bf1:3;
	unsigned int bf2:5;
};

int main() {
	int a = 1;
	int b = 2;

	/* locals */
	a += b;
	a -= 1;
	a *= 3;
	a /= 2;
	a %= 3;
	a &= 0xff;
	a |= 0x10;
	a ^= 0x1;
	a <<= 2;
	a >>= 1;

	/* right associative */
	a += (b += 4);

	/* globals */
	g += a;
	h <<= 1;
	h >>= 1;

	/* pointer deref */
	int *p = &g;
	*p += 7;
	*p >>= 1;

	/* array element (desugars to deref) */
	int arr[4];
	arr[0] = 1;
	arr[0] += 2;
	arr[1] = 8;
	arr[1] >>= 2;

	/* struct field */
	struct S s;
	s.x = 1;
	s.x += 2;
	s.y = 4;
	s.y |= 8;

	/* pointer-to-struct (->) */
	struct S *sp = &s;
	sp->x <<= 1;
	sp->y ^= 3;

	/* bitfield compound assignment */
	s.bf1 = 1;
	s.bf1 ^= 3;
	s.bf2 = 7;
	s.bf2 += 1;
	sp->bf1 |= 1;
	sp->bf2 <<= 1;

	return a + b + g + h + s.x + s.y + s.bf1 + s.bf2 + arr[0] + arr[1];
}

