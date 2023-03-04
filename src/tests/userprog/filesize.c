/* Tests that filesize will output the correct
    number of bytes for filesize.txt*/

#include <stdint.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
    int test = open("filesize.txt");
    int check = filesize(test);
    
    if (check == 58) {
        msg("Success");
        exit(0);
    }
    exit(-1);
}