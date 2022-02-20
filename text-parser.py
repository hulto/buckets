from audioop import add
from ipaddress import ip_address
from xml.etree import ElementTree as ET
from sklearn.cluster import KMeans

tree = ET.parse('./scans/10.10.0.0-24.xml')
root = tree.getroot()


# All cols for one hot.
import pandas as pd
import numpy as np

NUMBER_OF_SERVICEGROUPS=9
all_cols = []
all_indexes = []
all_indexes_indicies = {}
data = []

## Prepare all_colls and all_indexes
index = -1
# Iterate over hosts
for host in root.findall(".//host"):
    address = host.find("address")
    ip_address = f"{address.attrib['addr']}"
    # Iterate over ports for that host
    for port in host.findall("ports/port"):
        portstr = f"{port.attrib['portid']}/{port.attrib['protocol']}" #22/tcp
        status = f"{port.find('state').attrib['state']}"               #open | closed | filtered
        if status == "open":
            cpes = port.findall('.//cpe')                              #Get all cpe identifiers: ["cpe:/a:openbsd:openssh:8.2p1","cpe:/o:linux:linux_kernel"]
            cpestrs = []                                
            for cpe in cpes:
                cpestrs.append(cpe.text)
            cpe_arr = "|".join(cpestrs)                                 # Append these together to make a complex composite: cpe:/a:openbsd:openssh:8.2p1|cpe:/o:linux:linux_kernel

            if str(f"{portstr}-{status}-{cpe_arr}") not in all_cols:   # Check if this fingerprint doesn't exists in our array yet. If not make it.
                index+=1
                all_cols.append(f"{portstr}-{status}-{cpe_arr}")
            all_indexes.append(ip_address)                              # Add the ip address to our rows headres

# Loop again to make our one hot array.
all_rows = {}
for host in root.findall(".//host"):                            
    address = host.find("address")
    one_hot_arr = np.zeros(index+1)

    ip_address = f"{address.attrib['addr']}"
    for port in host.findall("ports/port"):
        portstr = f"{port.attrib['portid']}/{port.attrib['protocol']}"
        status = f"{port.find('state').attrib['state']}"
        if status == "open":
            cpes = port.findall('.//cpe')
            cpestrs = []
            for cpe in cpes:
                cpestrs.append(cpe.text)
            cpe_arr = "|".join(cpestrs)

            # Using the same fingerprint set our hot bit in the one hot array.
            one_hot_arr[all_cols.index(f"{portstr}-{status}-{cpe_arr}")] = 1
    # add data to dictionary.
    all_rows[ip_address] = one_hot_arr

res = pd.DataFrame.from_dict(all_rows, orient='index', columns=all_cols)
res.to_csv("./output/onehot.csv")

kmeans = KMeans(NUMBER_OF_SERVICEGROUPS)        # Do kmean clustering.
clusters = kmeans.fit_predict(res)
labels = pd.DataFrame(clusters)                 # Create pd data frame of labels
for index, row in labels.iterrows():            # Iterate over labels.
    print(f"{list(all_rows.keys())[index]}:{row[0]}")   #Use all_rows.keys() should be in the same order as when the one hot data frame was created.
