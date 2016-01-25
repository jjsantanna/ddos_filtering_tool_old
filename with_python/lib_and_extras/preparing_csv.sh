#!/bin/bash

folder=$1
cd $folder

ls -d */| while read subfolder 
do
	cd $subfolder #Open the folder
	cat .pig_header part-r-00000 > part-r-00000.csv #Join the header with the results into a csv file
	cd ..
done
