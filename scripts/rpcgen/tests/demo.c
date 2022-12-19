bool_t
xdr_TestEnum(XDR *xdrs, TestEnum *objp)
{
    if (!xdr_enum(xdrs, (enum_t *)objp))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStruct(XDR *xdrs, TestStruct *objp)
{
    if (!xdr_char(xdrs, &objp->c1))
        return FALSE;
    if (!xdr_char(xdrs, &objp->c2))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestUnion(XDR *xdrs, TestUnion *objp)
{
    if (!xdr_int(xdrs, &objp->type))
        return FALSE;
    switch (objp->type) {
    case 20:
        if (!xdr_int(xdrs, &objp->TestUnion_u.i1))
            return FALSE;
        break;
    case 30:
        if (!xdr_int(xdrs, &objp->TestUnion_u.i2))
            return FALSE;
        break;
    default:
        if (!xdr_int(xdrs, &objp->TestUnion_u.i3))
            return FALSE;
        break;
    }
    return TRUE;
}

bool_t
xdr_TestUnionVoidDefault(XDR *xdrs, TestUnionVoidDefault *objp)
{
    if (!xdr_int(xdrs, &objp->type))
        return FALSE;
    switch (objp->type) {
    case 21:
        if (!xdr_int(xdrs, &objp->TestUnionVoidDefault_u.i1))
            return FALSE;
        break;
    case 31:
        if (!xdr_int(xdrs, &objp->TestUnionVoidDefault_u.i2))
            return FALSE;
        break;
    default:
        break;
    }
    return TRUE;
}

bool_t
xdr_TestUnionNoDefault(XDR *xdrs, TestUnionNoDefault *objp)
{
    if (!xdr_int(xdrs, &objp->type))
        return FALSE;
    switch (objp->type) {
    case 22:
        if (!xdr_int(xdrs, &objp->TestUnionNoDefault_u.i1))
            return FALSE;
        break;
    case 32:
        if (!xdr_int(xdrs, &objp->TestUnionNoDefault_u.i2))
            return FALSE;
        break;
    default:
        return FALSE;
    }
    return TRUE;
}

bool_t
xdr_TestIntScalar(XDR *xdrs, TestIntScalar *objp)
{
    if (!xdr_int(xdrs, objp))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestIntPointer(XDR *xdrs, TestIntPointer *objp)
{
    if (!xdr_pointer(xdrs, (char **)objp, sizeof(int), (xdrproc_t)xdr_int))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestIntFixedArray(XDR *xdrs, TestIntFixedArray objp)
{
    if (!xdr_vector(xdrs, (char *)objp, 3,
        sizeof(int), (xdrproc_t)xdr_int))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestIntVariableArray(XDR *xdrs, TestIntVariableArray *objp)
{
    if (!xdr_array(xdrs, (char **)&objp->TestIntVariableArray_val, (u_int *) &objp->TestIntVariableArray_len, 5,
        sizeof(int), (xdrproc_t)xdr_int))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStringVariableArray(XDR *xdrs, TestStringVariableArray *objp)
{
    if (!xdr_string(xdrs, objp, 7))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestOpaqueFixedArray(XDR *xdrs, TestOpaqueFixedArray objp)
{
    if (!xdr_opaque(xdrs, objp, 9))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestOpaqueVariableArray(XDR *xdrs, TestOpaqueVariableArray *objp)
{
    if (!xdr_bytes(xdrs, (char **)&objp->TestOpaqueVariableArray_val, (u_int *) &objp->TestOpaqueVariableArray_len, 11))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestEnumScalar(XDR *xdrs, TestEnumScalar *objp)
{
    if (!xdr_TestEnum(xdrs, objp))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestEnumPointer(XDR *xdrs, TestEnumPointer *objp)
{
    if (!xdr_pointer(xdrs, (char **)objp, sizeof(TestEnum), (xdrproc_t)xdr_TestEnum))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestEnumFixedArray(XDR *xdrs, TestEnumFixedArray objp)
{
    if (!xdr_vector(xdrs, (char *)objp, 13,
        sizeof(TestEnum), (xdrproc_t)xdr_TestEnum))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestEnumVariableArray(XDR *xdrs, TestEnumVariableArray *objp)
{
    if (!xdr_array(xdrs, (char **)&objp->TestEnumVariableArray_val, (u_int *) &objp->TestEnumVariableArray_len, 15,
        sizeof(TestEnum), (xdrproc_t)xdr_TestEnum))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStructScalar(XDR *xdrs, TestStructScalar *objp)
{
    if (!xdr_TestStruct(xdrs, objp))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStructPointer(XDR *xdrs, TestStructPointer *objp)
{
    if (!xdr_pointer(xdrs, (char **)objp, sizeof(TestStruct), (xdrproc_t)xdr_TestStruct))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStructFixedArray(XDR *xdrs, TestStructFixedArray objp)
{
    if (!xdr_vector(xdrs, (char *)objp, 17,
        sizeof(TestStruct), (xdrproc_t)xdr_TestStruct))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStructVariableArray(XDR *xdrs, TestStructVariableArray *objp)
{
    if (!xdr_array(xdrs, (char **)&objp->TestStructVariableArray_val, (u_int *) &objp->TestStructVariableArray_len, 19,
        sizeof(TestStruct), (xdrproc_t)xdr_TestStruct))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestUnionScalar(XDR *xdrs, TestUnionScalar *objp)
{
    if (!xdr_TestUnion(xdrs, objp))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestUnionPointer(XDR *xdrs, TestUnionPointer *objp)
{
    if (!xdr_pointer(xdrs, (char **)objp, sizeof(TestUnion), (xdrproc_t)xdr_TestUnion))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestUnionFixedArray(XDR *xdrs, TestUnionFixedArray objp)
{
    if (!xdr_vector(xdrs, (char *)objp, 21,
        sizeof(TestUnion), (xdrproc_t)xdr_TestUnion))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestUnionVariableArray(XDR *xdrs, TestUnionVariableArray *objp)
{
    if (!xdr_array(xdrs, (char **)&objp->TestUnionVariableArray_val, (u_int *) &objp->TestUnionVariableArray_len, 23,
        sizeof(TestUnion), (xdrproc_t)xdr_TestUnion))
        return FALSE;
    return TRUE;
}

bool_t
xdr_TestStructAllTypes(XDR *xdrs, TestStructAllTypes *objp)
{
    if (!xdr_char(xdrs, &objp->sc))
        return FALSE;
    if (!xdr_u_char(xdrs, &objp->suc))
        return FALSE;
    if (!xdr_short(xdrs, &objp->ss))
        return FALSE;
    if (!xdr_u_short(xdrs, &objp->sus))
        return FALSE;
    if (!xdr_int(xdrs, &objp->si))
        return FALSE;
    if (!xdr_u_int(xdrs, &objp->sui))
        return FALSE;
    if (!xdr_int64_t(xdrs, &objp->sh))
        return FALSE;
    if (!xdr_uint64_t(xdrs, &objp->suh))
        return FALSE;
    if (!xdr_bool(xdrs, &objp->sb))
        return FALSE;
    if (!xdr_float(xdrs, &objp->sf))
        return FALSE;
    if (!xdr_double(xdrs, &objp->sd))
        return FALSE;
    if (!xdr_pointer(xdrs, (char **)&objp->ip, sizeof(int), (xdrproc_t)xdr_int))
        return FALSE;
    if (!xdr_vector(xdrs, (char *)objp->ifa, TestConstDec,
        sizeof(int), (xdrproc_t)xdr_int))
        return FALSE;
    if (!xdr_array(xdrs, (char **)&objp->iva.iva_val, (u_int *) &objp->iva.iva_len, TestConstHex,
        sizeof(int), (xdrproc_t)xdr_int))
        return FALSE;
    if (!xdr_string(xdrs, &objp->stva, TestConstOct))
        return FALSE;
    if (!xdr_opaque(xdrs, objp->ofa, 33))
        return FALSE;
    if (!xdr_bytes(xdrs, (char **)&objp->ova.ova_val, (u_int *) &objp->ova.ova_len, 35))
        return FALSE;
    if (!xdr_TestEnum(xdrs, &objp->e1))
        return FALSE;
    if (!xdr_TestEnum(xdrs, &objp->e2))
        return FALSE;
    if (!xdr_pointer(xdrs, (char **)&objp->ep, sizeof(TestEnum), (xdrproc_t)xdr_TestEnum))
        return FALSE;
    if (!xdr_vector(xdrs, (char *)objp->efa, 37,
        sizeof(TestEnum), (xdrproc_t)xdr_TestEnum))
        return FALSE;
    if (!xdr_array(xdrs, (char **)&objp->eva.eva_val, (u_int *) &objp->eva.eva_len, 39,
        sizeof(TestEnum), (xdrproc_t)xdr_TestEnum))
        return FALSE;
    if (!xdr_TestStruct(xdrs, &objp->s))
        return FALSE;
    if (!xdr_pointer(xdrs, (char **)&objp->sp, sizeof(TestStruct), (xdrproc_t)xdr_TestStruct))
        return FALSE;
    if (!xdr_vector(xdrs, (char *)objp->sfa, 41,
        sizeof(TestStruct), (xdrproc_t)xdr_TestStruct))
        return FALSE;
    if (!xdr_array(xdrs, (char **)&objp->sva.sva_val, (u_int *) &objp->sva.sva_len, 43,
        sizeof(TestStruct), (xdrproc_t)xdr_TestStruct))
        return FALSE;
    if (!xdr_TestUnion(xdrs, &objp->u))
        return FALSE;
    if (!xdr_pointer(xdrs, (char **)&objp->up, sizeof(TestUnion), (xdrproc_t)xdr_TestUnion))
        return FALSE;
    if (!xdr_vector(xdrs, (char *)objp->ufa, 45,
        sizeof(TestUnion), (xdrproc_t)xdr_TestUnion))
        return FALSE;
    if (!xdr_array(xdrs, (char **)&objp->uva.uva_val, (u_int *) &objp->uva.uva_len, 47,
        sizeof(TestUnion), (xdrproc_t)xdr_TestUnion))
        return FALSE;
    if (!xdr_TestIntScalar(xdrs, &objp->tis))
        return FALSE;
    if (!xdr_TestIntPointer(xdrs, &objp->tip))
        return FALSE;
    if (!xdr_TestIntFixedArray(xdrs, objp->tifa))
        return FALSE;
    if (!xdr_TestIntVariableArray(xdrs, &objp->tiva))
        return FALSE;
    if (!xdr_TestStringVariableArray(xdrs, &objp->tstva))
        return FALSE;
    if (!xdr_TestOpaqueFixedArray(xdrs, objp->tofa))
        return FALSE;
    if (!xdr_TestOpaqueVariableArray(xdrs, &objp->tova))
        return FALSE;
    if (!xdr_TestEnumScalar(xdrs, &objp->tes))
        return FALSE;
    if (!xdr_TestEnumPointer(xdrs, &objp->tep))
        return FALSE;
    if (!xdr_TestEnumFixedArray(xdrs, objp->tefa))
        return FALSE;
    if (!xdr_TestEnumVariableArray(xdrs, &objp->teva))
        return FALSE;
    if (!xdr_TestStructScalar(xdrs, &objp->tss))
        return FALSE;
    if (!xdr_TestStructPointer(xdrs, &objp->tsp))
        return FALSE;
    if (!xdr_TestStructFixedArray(xdrs, objp->tsfa))
        return FALSE;
    if (!xdr_TestStructVariableArray(xdrs, &objp->tsva))
        return FALSE;
    if (!xdr_TestUnionScalar(xdrs, &objp->tu))
        return FALSE;
    if (!xdr_TestUnionPointer(xdrs, &objp->tup))
        return FALSE;
    if (!xdr_TestUnionFixedArray(xdrs, objp->tufa))
        return FALSE;
    if (!xdr_TestUnionVariableArray(xdrs, &objp->tuva))
        return FALSE;
    return TRUE;
}
