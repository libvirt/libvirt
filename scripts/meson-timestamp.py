#!/usr/bin/env python3

import os
from datetime import datetime, timezone

timestamp = os.environ.get('SOURCE_DATE_EPOCH', None)
timeformat = '%c %Z'

if timestamp:
    print(datetime.fromtimestamp(int(timestamp), tz=timezone.utc).strftime(timeformat))
else:
    print(datetime.now(tz=timezone.utc).strftime(timeformat))
