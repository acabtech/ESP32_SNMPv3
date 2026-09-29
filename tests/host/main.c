// main.c — host test runner (M1).
//
// Build:  make            (from tests/host)
// Run:    ./build/test_runner
//
// SPDX-License-Identifier: GPL-3.0
#include <stdio.h>

int test_soft(void);
int test_ber(void);
int test_usm(void);
int test_mib(void);
int test_agent(void);

int main(void) {
  int fails = 0;
  fails += test_soft();
  fails += test_ber();
  fails += test_usm();
  fails += test_mib();
  fails += test_agent();
  if (fails == 0) {
    printf("\nALL HOST TESTS PASSED\n");
    return 0;
  }
  printf("\n%d FAILURE(S)\n", fails);
  return 1;
}