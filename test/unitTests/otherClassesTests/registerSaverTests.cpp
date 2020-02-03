#include "../catch.hpp"
#include <sys/user.h>
#include "../../../include/registerSaver.hpp"


/**
 * Tests for the class registerSaver
 */

TEST_CASE("registerSaver throws errors when appropriate", "registerSaver"){
  registerSaver rs;

  SECTION("empty pop throws error"){
    REQUIRE_THROWS_WITH( rs.popRegisterState(), "dettrace runtime exception: Attempting to pop from an empty registerSaver.\n");
  }

  SECTION("full push throws error"){
    struct user_regs_struct regs;
    rs.pushRegisterState(regs);
    REQUIRE_THROWS_WITH( rs.pushRegisterState(regs), "dettrace runtime exception: Attempting to push to a filed registerSaver.\n");
  }

}

TEST_CASE("registerSaver retrieves what is pushed correctly", "registerSaver"){
  registerSaver rs;

  SECTION("push -> pop returns correct state"){
    struct user_regs_struct original = {0xaa, 0xbb, 0xcc};
    rs.pushRegisterState(original);

    struct user_regs_struct returned = rs.popRegisterState();
    
    REQUIRE(original.r15 == returned.r15);
    REQUIRE(original.r14 == returned.r14);
    REQUIRE(original.r13 == returned.r13);
    REQUIRE(original.rsp == returned.rsp);
    REQUIRE(original.rip == returned.rip);


    SECTION("push -> pop -> push -> pop returnes correct state"){
      struct user_regs_struct second = {0xdd, 0xee, 0xff};
      rs.pushRegisterState(second);
      
      struct user_regs_struct returned_second = rs.popRegisterState();
      
      REQUIRE(second.r15 == returned_second.r15);
      REQUIRE(second.r14 == returned_second.r14);
      REQUIRE(second.r13 == returned_second.r13);
      REQUIRE(second.rsp == returned_second.rsp);
      REQUIRE(second.rip == returned_second.rip);

    }

  }
 
}

TEST_CASE("registerSaver has a deep copy of values", "registerSaver"){
  registerSaver rs;

  SECTION("modifications to original afte push don't show in pop"){
    struct user_regs_struct original = {0, 1, 2, 3, 4};
    rs.pushRegisterState(original);

    original.rsp = 0xfff;
    original.rip = 0x123;

    struct user_regs_struct returned = rs.popRegisterState();

    REQUIRE(original.rsp != returned.rsp);
    REQUIRE(original.rip != returned.rip);
  }

  SECTION("returned struct does not point to original one"){
    struct user_regs_struct original = {0, 1, 2, 3, 4};
    rs.pushRegisterState(original);
    struct user_regs_struct returned = rs.popRegisterState();
    
    REQUIRE(&original != &returned);
  }
}
