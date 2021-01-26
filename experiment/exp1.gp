reset
set ylabel 'time(ns)'
set title 'FlexSC vs normal system call'
set key left top
set term png enhanced font 'Verdana,10'
set output 'exp1.png'

plot [:][:] \
'normal.out' using ($0+1):1 with linespoints linewidth 2 title "Normal syscall",\
#'experiment/flexsc.out' using ($0+1):2 with linespoints linewidth 2 title "FlexSC syscall"