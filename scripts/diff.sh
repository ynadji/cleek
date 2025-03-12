#!/bin/bash

# close time is based on when CLEEK was run.
diff <(grep -v '^#close' "${1}") <(grep -v '^#close' "${2}")
