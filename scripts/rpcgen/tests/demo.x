enum TestEnum {
  TEST_ENUM_ONE = 1,
  TEST_ENUM_TWO = 2
};

struct TestStruct {
  char c1;
  char c2;
};

union TestUnion switch (int type) {
 case 20:
    int i1;
 case 30:
    int i2;
 default:
    int i3;
};

union TestUnionVoidDefault switch (int type) {
 case 21:
    int i1;
 case 31:
    int i2;
 default:
    void;
};

union TestUnionNoDefault switch (int type) {
 case 22:
    int i1;
 case 32:
    int i2;
};

typedef int TestIntScalar;
typedef int *TestIntPointer;
typedef int TestIntFixedArray[3];
typedef int TestIntVariableArray<5>;

typedef string TestStringVariableArray<7>;

typedef opaque TestOpaqueFixedArray[9];
typedef opaque TestOpaqueVariableArray<11>;

typedef TestEnum TestEnumScalar;
typedef TestEnum *TestEnumPointer;
typedef TestEnum TestEnumFixedArray[13];
typedef TestEnum TestEnumVariableArray<15>;

typedef TestStruct TestStructScalar;
typedef TestStruct *TestStructPointer;
typedef TestStruct TestStructFixedArray[17];
typedef TestStruct TestStructVariableArray<19>;

typedef TestUnion TestUnionScalar;
typedef TestUnion *TestUnionPointer;
typedef TestUnion TestUnionFixedArray[21];
typedef TestUnion TestUnionVariableArray<23>;

const TestConstDec = 25;
const TestConstHex = 0x27;
const TestConstOct = 031;

struct TestStructAllTypes {
  char sc;
  unsigned char suc;
  short ss;
  unsigned short sus;
  int si;
  unsigned int sui;
  hyper sh;
  unsigned hyper suh;
  bool sb;
  float sf;
  double sd;

  int *ip;
  int ifa[TestConstDec];
  int iva<TestConstHex>;

  string stva<TestConstOct>;

  opaque ofa[33];
  opaque ova<35>;

  TestEnum e1;
  TestEnum e2;
  TestEnum *ep;
  TestEnum efa[37];
  TestEnum eva<39>;

  TestStruct s;
  TestStruct *sp;
  TestStruct sfa[41];
  TestStruct sva<43>;

  TestUnion u;
  TestUnion *up;
  TestUnion ufa[45];
  TestUnion uva<47>;

  TestIntScalar tis;
  TestIntPointer tip;
  TestIntFixedArray tifa;
  TestIntVariableArray tiva;

  TestStringVariableArray tstva;

  TestOpaqueFixedArray tofa;
  TestOpaqueVariableArray tova;

  TestEnumScalar tes;
  TestEnumPointer tep;
  TestEnumFixedArray tefa;
  TestEnumVariableArray teva;

  TestStructScalar tss;
  TestStructPointer tsp;
  TestStructFixedArray tsfa;
  TestStructVariableArray tsva;

  TestUnionScalar tu;
  TestUnionPointer tup;
  TestUnionFixedArray tufa;
  TestUnionVariableArray tuva;
};
