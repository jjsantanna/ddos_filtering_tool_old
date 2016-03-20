
#!/bin/bash 

data_folder=$1
cd $data_folder
output_file=`basename "$PWD"`".txt"

find . -name '*.DS_Store' -type f -delete

nfdump -R $data_folder -q -N -o csv 'ipv4 AND DST NET 145.58.0.0/16 AND NOT SRC NET 145.58.0.0/16 '|
awk -F , '{cmd ="date -d  \""$1"\" +\"%s\" " ; cmd | getline var; print var","$3","$8","$4","$5","$6","$7","$12","$13","$9","$11; close(cmd) }'>> ../$output_file
