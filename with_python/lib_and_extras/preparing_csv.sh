
#!/bin/bash

cd output_example 

ls -d */| while read folder 
do
	cd $folder #open the analysis folder of one pcap
	ls -d */| while read folder #For each folder into the analysis...
	do
		cd $folder #Open the folder
		cat .pig_header part-r-00000 > part-r-00000.csv #Join the header with the results into a csv file
		cd ..
	done
	cd ..
done
