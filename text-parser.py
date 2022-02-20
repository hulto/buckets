from audioop import add
from ipaddress import ip_address
from xml.etree import ElementTree as ET
from sklearn.cluster import KMeans

tree = ET.parse('./scans/10.10.0.0-24.xml')
root = tree.getroot()


# for host in root.findall("hosthint"):
#     print(host.find('status').attrib['state'])
#     print(host.find('address').attrib['addr'])

# All cols for one hot.
import pandas as pd
import numpy as np
NUMBER_OF_SERVICEGROUPS=9
all_cols = []
all_cols_indicies = {}
all_indexes = []
all_indexes_indicies = {}
data = []

# for cpe in root.findall(".//cpe"):
#     print(cpe.text)
index = -1
for host in root.findall(".//host"):
    address = host.find("address")
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
            #print(f"{ip_address},{portstr},{status},{cpe_arr}")
            if str(f"{portstr}-{status}-{cpe_arr}") not in all_cols_indicies:
                index+=1
                all_cols_indicies[f"{portstr}-{status}-{cpe_arr}"] = index
                all_cols.append(f"{portstr}-{status}-{cpe_arr}")
            all_indexes.append(ip_address)

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

            #one_hot_arr[all_cols_indicies[f"{portstr}-{status}-{cpe_arr}"]] = 1
            one_hot_arr[all_cols.index(f"{portstr}-{status}-{cpe_arr}")] = 1
            # all_rows[ip_address] = one_hot_arr
            #print(f"{ip_address},{portstr},{status},{cpe_arr}")
            # all_cols.append(f"{portstr}-{status}-{cpe_arr}")
    all_rows[ip_address] = one_hot_arr

res = pd.DataFrame.from_dict(all_rows, orient='index', columns=all_cols)
res.to_csv("./output/onehot.csv")

kmeans = KMeans(NUMBER_OF_SERVICEGROUPS)
clusters = kmeans.fit_predict(res)
labels = pd.DataFrame(clusters)
for index, row in labels.iterrows():
    print(f"{list(all_rows.keys())[index]}:{row[0]}")

# for p in root.findall('.nmaprun'):
#     print("%s | %s" % (p.find('Name').text, p.find('Value').text))
