# buckets
create service group buckets based on scans

## How it works.
Given an nmap scan xml output.
`nmap -sV -sC -p22,443,53,111,3306,21,23,445,25,5432,445,587,465 -T5 10.10.0.0/24 -oX ./scans/10.10.0.0-24.xml`
parse-text.py reads in the xml, finds all open ports for each host and records the cpe identifiers associated with them.
This data is then put into a one hot format with each port-status-cpelist being represented by a column.
We then use the sklearn KMeans alogorithm to create a `NUMBER_OF_SERVICEGROUPS` number of groupings based on the similarity of services running on each port.
