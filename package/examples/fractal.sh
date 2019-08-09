#!/bin/bash

# Original:
# -0.743643925055 0.131825905901 5.08373779904306E-08 5.08373779904306E-08

# Black screen:
# -0.2 -0.2 0.1 0.1

cat > frac.config <<EOF
c075
mandelbrot
-0.743643925055 0.131825905901 5.08373779904306E-08 5.08373779904306E-08
64 7500
1
0x0
iterationcount
smooth
squareroot
0.035 0
0 0x389f 0.25 0xffffff 0.5 0xfffd42 0.75 0xbe0700 1 0x389f

EOF

fractalnow -j 1 -c ./frac.config -x 200 -y 200 -o test.ppm
