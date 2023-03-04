/* Pass a nonexistent file desrcriptor. 
    The function shoudl return -1. */

#include <stdint.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    int check = filesize(300);
    if (check == -1) {
        exit(-1);
    }
}