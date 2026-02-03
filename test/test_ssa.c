// int max(int a, int b) {
//     int c = a;
//     if (c > 1)
//         c = a + 1;
//     else
//         c = b - 1;
//     int d = c + 1;
//     return d;
// }

// int main() {
//     int x = 5;
//     int y = 7;
//     int m = max(x, y);

//     return m;
// }

// // 测试循环结构
// int sum_loop(int n) {
//     int sum = 0;
//     int i = 0;
//     while (i < n) {
//         sum = sum + i;
//         i = i + 1;
//     }
//     return sum;
// }

// // 测试嵌套条件
// int nested_if(int x, int y) {
//     int result = 0;
//     if (x > 0) {
//         if (y > 0) {
//             result = x + y;
//         } else {
//             result = x - y;
//         }
//     } else {
//         result = 1;
//     }
//     return result;
// }

// 测试for循环和break/continue
int find_first_even(int arr[], int size) {
    int i;
    for (i = 0; i < size; i = i + 1) {
        if (arr[i] % 2 == 0) {
            break;
        }
    }
    return i;
}

// // // 测试复杂表达式和类型转换
// // int complex_expr(int a, int b, int c) {
// //     int result = (a > b) ? ((c > 0) ? a + c : b - c) : ((a + b) * c);
// //     return result;
// // }

// // 测试指针和数组
// int array_sum(int arr[], int n) {
//     int sum = 0;
//     int i = 0;
//     while (i < n) {
//         sum = sum + arr[i];
//         i = i + 1;
//     }
//     return sum;
// }

// // 测试位运算
// int bit_operations(int x, int y) {
//     int and_result = x & y;
//     int or_result = x | y;
//     int xor_result = x ^ y;
//     int shift_left = x << 2;
//     int shift_right = y >> 1;
//     return (and_result + or_result) ^ (xor_result | shift_left) & shift_right;
// }

// // // 测试递归（简单阶乘）
// // int factorial(int n) {
// //     if (n <= 1) {
// //         return 1;
// //     } else {
// //         return n * factorial(n - 1);
// //     }
// // }

// // 测试多个返回路径
// int multi_return(int x) {
//     if (x < 0) {
//         return 0;
//     } else if (x == 0) {
//         return 1;
//     } else {
//         return 2;
//     }
// }

// // 测试循环中的条件判断
// int count_positives(int arr[], int n) {
//     int count = 0;
//     int i = 0;
//     while (i < n) {
//         if (arr[i] > 0) {
//             count = count + 1;
//         }
//         i = i + 1;
//     }
//     return count;
// }

// // 测试复杂控制流
// int complex_control_flow(int x, int y) {
//     int result = 0;
//     int i = 0;
    
//     while (i < x) {
//         if (i % 2 == 0) {
//             result = result + y;
//             if (result > 100) {
//                 break;
//             }
//         } else {
//             result = result - 1;
//         }
//         i = i + 1;
//     }
    
//     if (result < 0) {
//         result = 0;
//     }
    
//     return result;
// }