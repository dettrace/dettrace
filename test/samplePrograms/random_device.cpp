#include <iostream>
#include <random>

int main() {

  std::uniform_int_distribution<int> d(0, 1000000);

  std::random_device rd1; // without any ctor args, appears to use RDRND
  for (int n = 0; n < 10; ++n) {
    std::cout << d(rd1) << ' ';
  }
  std::cout << std::endl;

  return 0;
}
