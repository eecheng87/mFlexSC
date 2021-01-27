set ylabel 'time(ns)'
set title 'FlexSC vs normal system call'
set term png enhanced font 'Verdana,10'
set style data boxplot
set style boxplot outliers

unset key
set xtics ("normal syscall" 1, "FlexSC syscall" 2) scale 0.0

set output 'exp2.png'
set yrange [0:150000]

plot \
'normal.out' using (1):1 ,\
'flexsc.out' using (2):1 ,\

