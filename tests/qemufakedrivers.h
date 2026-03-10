/*
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "driver.h"

virSecretDriver *
testQemuGetFakeSecretDriver(void);

virStorageDriver *
testQemuGetFakeStorageDriver(void);

virNWFilterDriver *
testQemuGetFakeNWFilterDriver(void);

virNetworkDriver *
testQemuGetFakeNetworkDriver(void);
