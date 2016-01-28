#!/bin/bash
cd output

ls -d */| while read folder 
do
	cd $folder
	ls -d */| while read folder 
	do
		cd $folder
		cat .pig_header part-r-00000 > part-r-00000.csv
		cd ..
	done
	cd ..
done
