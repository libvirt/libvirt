enum TestEnum {
    TEST_ENUM_ONE = 1,
    TEST_ENUM_TWO = 2,
};
typedef enum TestEnum TestEnum;

struct TestStruct {
    char c1;
    char c2;
};
typedef struct TestStruct TestStruct;

struct TestUnion {
    int type;
    union {
        int i1;
        int i2;
        int i3;
    } TestUnion_u;
};
typedef struct TestUnion TestUnion;

struct TestUnionVoidDefault {
    int type;
    union {
        int i1;
        int i2;
    } TestUnionVoidDefault_u;
};
typedef struct TestUnionVoidDefault TestUnionVoidDefault;

struct TestUnionNoDefault {
    int type;
    union {
        int i1;
        int i2;
    } TestUnionNoDefault_u;
};
typedef struct TestUnionNoDefault TestUnionNoDefault;

typedef int TestIntScalar;

typedef int *TestIntPointer;

typedef int TestIntFixedArray[3];

typedef struct {
    u_int TestIntVariableArray_len;
    int *TestIntVariableArray_val;
} TestIntVariableArray;

typedef char *TestStringVariableArray;

typedef char TestOpaqueFixedArray[9];

typedef struct {
    u_int TestOpaqueVariableArray_len;
    char *TestOpaqueVariableArray_val;
} TestOpaqueVariableArray;

typedef TestEnum TestEnumScalar;

typedef TestEnum *TestEnumPointer;

typedef TestEnum TestEnumFixedArray[13];

typedef struct {
    u_int TestEnumVariableArray_len;
    TestEnum *TestEnumVariableArray_val;
} TestEnumVariableArray;

typedef TestStruct TestStructScalar;

typedef TestStruct *TestStructPointer;

typedef TestStruct TestStructFixedArray[17];

typedef struct {
    u_int TestStructVariableArray_len;
    TestStruct *TestStructVariableArray_val;
} TestStructVariableArray;

typedef TestUnion TestUnionScalar;

typedef TestUnion *TestUnionPointer;

typedef TestUnion TestUnionFixedArray[21];

typedef struct {
    u_int TestUnionVariableArray_len;
    TestUnion *TestUnionVariableArray_val;
} TestUnionVariableArray;

#define TestConstDec 25

#define TestConstHex 0x27

#define TestConstOct 031

struct TestStructAllTypes {
    char sc;
    u_char suc;
    short ss;
    u_short sus;
    int si;
    u_int sui;
    int64_t sh;
    uint64_t suh;
    bool_t sb;
    float sf;
    double sd;
    int *ip;
    int ifa[TestConstDec];
    struct {
        u_int iva_len;
        int *iva_val;
    } iva;
    char *stva;
    char ofa[33];
    struct {
        u_int ova_len;
        char *ova_val;
    } ova;
    TestEnum e1;
    TestEnum e2;
    TestEnum *ep;
    TestEnum efa[37];
    struct {
        u_int eva_len;
        TestEnum *eva_val;
    } eva;
    TestStruct s;
    TestStruct *sp;
    TestStruct sfa[41];
    struct {
        u_int sva_len;
        TestStruct *sva_val;
    } sva;
    TestUnion u;
    TestUnion *up;
    TestUnion ufa[45];
    struct {
        u_int uva_len;
        TestUnion *uva_val;
    } uva;
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
typedef struct TestStructAllTypes TestStructAllTypes;

extern  bool_t xdr_TestEnum(XDR *, TestEnum*);

extern  bool_t xdr_TestStruct(XDR *, TestStruct*);

extern  bool_t xdr_TestUnion(XDR *, TestUnion*);

extern  bool_t xdr_TestUnionVoidDefault(XDR *, TestUnionVoidDefault*);

extern  bool_t xdr_TestUnionNoDefault(XDR *, TestUnionNoDefault*);

extern  bool_t xdr_TestIntScalar(XDR *, TestIntScalar*);

extern  bool_t xdr_TestIntPointer(XDR *, TestIntPointer*);

extern  bool_t xdr_TestIntFixedArray(XDR *, TestIntFixedArray);

extern  bool_t xdr_TestIntVariableArray(XDR *, TestIntVariableArray*);

extern  bool_t xdr_TestStringVariableArray(XDR *, TestStringVariableArray*);

extern  bool_t xdr_TestOpaqueFixedArray(XDR *, TestOpaqueFixedArray);

extern  bool_t xdr_TestOpaqueVariableArray(XDR *, TestOpaqueVariableArray*);

extern  bool_t xdr_TestEnumScalar(XDR *, TestEnumScalar*);

extern  bool_t xdr_TestEnumPointer(XDR *, TestEnumPointer*);

extern  bool_t xdr_TestEnumFixedArray(XDR *, TestEnumFixedArray);

extern  bool_t xdr_TestEnumVariableArray(XDR *, TestEnumVariableArray*);

extern  bool_t xdr_TestStructScalar(XDR *, TestStructScalar*);

extern  bool_t xdr_TestStructPointer(XDR *, TestStructPointer*);

extern  bool_t xdr_TestStructFixedArray(XDR *, TestStructFixedArray);

extern  bool_t xdr_TestStructVariableArray(XDR *, TestStructVariableArray*);

extern  bool_t xdr_TestUnionScalar(XDR *, TestUnionScalar*);

extern  bool_t xdr_TestUnionPointer(XDR *, TestUnionPointer*);

extern  bool_t xdr_TestUnionFixedArray(XDR *, TestUnionFixedArray);

extern  bool_t xdr_TestUnionVariableArray(XDR *, TestUnionVariableArray*);

extern  bool_t xdr_TestStructAllTypes(XDR *, TestStructAllTypes*);
