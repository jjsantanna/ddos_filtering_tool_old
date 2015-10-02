#!/bin/bash

ls -d */| while read folder 
do
	cd $folder
	cat .pig_header part-r-00000 > part-r-00000.csv
	cd ..
done
