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
void xdr_TestStruct_clear(TestStruct *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStruct, xdr_TestStruct_clear);

struct TestUnion {
    int type;
    union {
        int i1;
        int i2;
        int i3;
    } TestUnion_u;
};
typedef struct TestUnion TestUnion;
void xdr_TestUnion_clear(TestUnion *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnion, xdr_TestUnion_clear);

struct TestUnionVoidDefault {
    int type;
    union {
        int i1;
        int i2;
    } TestUnionVoidDefault_u;
};
typedef struct TestUnionVoidDefault TestUnionVoidDefault;
void xdr_TestUnionVoidDefault_clear(TestUnionVoidDefault *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnionVoidDefault, xdr_TestUnionVoidDefault_clear);

struct TestUnionNoDefault {
    int type;
    union {
        int i1;
        int i2;
    } TestUnionNoDefault_u;
};
typedef struct TestUnionNoDefault TestUnionNoDefault;
void xdr_TestUnionNoDefault_clear(TestUnionNoDefault *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnionNoDefault, xdr_TestUnionNoDefault_clear);

typedef int TestIntScalar;
void xdr_TestIntScalar_clear(TestIntScalar *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestIntScalar, xdr_TestIntScalar_clear);

typedef int *TestIntPointer;
void xdr_TestIntPointer_clear(TestIntPointer *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestIntPointer, xdr_TestIntPointer_clear);

typedef int TestIntFixedArray[3];
void xdr_TestIntFixedArray_clear(TestIntFixedArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestIntFixedArray, xdr_TestIntFixedArray_clear);

typedef struct {
    u_int TestIntVariableArray_len;
    int *TestIntVariableArray_val;
} TestIntVariableArray;
void xdr_TestIntVariableArray_clear(TestIntVariableArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestIntVariableArray, xdr_TestIntVariableArray_clear);

typedef char *TestStringVariableArray;
void xdr_TestStringVariableArray_clear(TestStringVariableArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStringVariableArray, xdr_TestStringVariableArray_clear);

typedef char TestOpaqueFixedArray[9];
void xdr_TestOpaqueFixedArray_clear(TestOpaqueFixedArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestOpaqueFixedArray, xdr_TestOpaqueFixedArray_clear);

typedef struct {
    u_int TestOpaqueVariableArray_len;
    char *TestOpaqueVariableArray_val;
} TestOpaqueVariableArray;
void xdr_TestOpaqueVariableArray_clear(TestOpaqueVariableArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestOpaqueVariableArray, xdr_TestOpaqueVariableArray_clear);

typedef TestEnum TestEnumScalar;
void xdr_TestEnumScalar_clear(TestEnumScalar *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestEnumScalar, xdr_TestEnumScalar_clear);

typedef TestEnum *TestEnumPointer;
void xdr_TestEnumPointer_clear(TestEnumPointer *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestEnumPointer, xdr_TestEnumPointer_clear);

typedef TestEnum TestEnumFixedArray[13];
void xdr_TestEnumFixedArray_clear(TestEnumFixedArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestEnumFixedArray, xdr_TestEnumFixedArray_clear);

typedef struct {
    u_int TestEnumVariableArray_len;
    TestEnum *TestEnumVariableArray_val;
} TestEnumVariableArray;
void xdr_TestEnumVariableArray_clear(TestEnumVariableArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestEnumVariableArray, xdr_TestEnumVariableArray_clear);

typedef TestStruct TestStructScalar;
void xdr_TestStructScalar_clear(TestStructScalar *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStructScalar, xdr_TestStructScalar_clear);

typedef TestStruct *TestStructPointer;
void xdr_TestStructPointer_clear(TestStructPointer *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStructPointer, xdr_TestStructPointer_clear);

typedef TestStruct TestStructFixedArray[17];
void xdr_TestStructFixedArray_clear(TestStructFixedArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStructFixedArray, xdr_TestStructFixedArray_clear);

typedef struct {
    u_int TestStructVariableArray_len;
    TestStruct *TestStructVariableArray_val;
} TestStructVariableArray;
void xdr_TestStructVariableArray_clear(TestStructVariableArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStructVariableArray, xdr_TestStructVariableArray_clear);

typedef TestUnion TestUnionScalar;
void xdr_TestUnionScalar_clear(TestUnionScalar *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnionScalar, xdr_TestUnionScalar_clear);

typedef TestUnion *TestUnionPointer;
void xdr_TestUnionPointer_clear(TestUnionPointer *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnionPointer, xdr_TestUnionPointer_clear);

typedef TestUnion TestUnionFixedArray[21];
void xdr_TestUnionFixedArray_clear(TestUnionFixedArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnionFixedArray, xdr_TestUnionFixedArray_clear);

typedef struct {
    u_int TestUnionVariableArray_len;
    TestUnion *TestUnionVariableArray_val;
} TestUnionVariableArray;
void xdr_TestUnionVariableArray_clear(TestUnionVariableArray *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestUnionVariableArray, xdr_TestUnionVariableArray_clear);

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
void xdr_TestStructAllTypes_clear(TestStructAllTypes *objp);
G_DEFINE_AUTO_CLEANUP_CLEAR_FUNC(TestStructAllTypes, xdr_TestStructAllTypes_clear);

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
