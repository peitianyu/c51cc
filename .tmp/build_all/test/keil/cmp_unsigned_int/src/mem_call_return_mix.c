typedef unsigned char u8;
typedef unsigned int u16;

u16 g16;
u16 arr16[4];

u16 ret_widen(u8 x) {
    return x;
}

u16 id16(u16 x) {
    return x;
}

u16 call_widen(u8 x) {
    return id16(x);
}

void store_global_widen(u8 x) {
    g16 = x;
}

u16 store_then_load_global(u8 x) {
    g16 = x;
    return g16;
}

u16 ptr_store_then_load(u8 x) {
    u16 local = 0;
    u16* p = &local;
    *p = x;
    return *p;
}

u16 gep_store_then_load(u8 idx, u8 x) {
    arr16[idx] = x;
    return arr16[idx];
}

int main()
{
    return 0;
}