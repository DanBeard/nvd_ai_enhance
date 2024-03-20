import csv
import json 
import traceback

#stats_filename = "./stats-2023-bak-1000-examples1.csv"
stats_filename = "./stats-2023.csv"

def cpe_prefix(cpe):
    # massage from old CPE string to new cpeString
    if cpe.startswith("cpe:/a"):
        cpe_split = cpe.split(":")
        if len(cpe_split) >= 4:
            cpe = f"cpe:2.3:a:{cpe_split[2]}:{cpe_split[3]}:-:*:*:*:*:*:*:*"

    elif cpe.startswith('cpe:/o:paloaltonetworks:panos'):
        cpe = 'cpe:2.3:o:paloaltonetworks:pan-os'
    return ":".join(cpe.split(":")[0:5])


with open(stats_filename,'r') as sfile:
    reader = csv.DictReader(sfile)

    # stats
    num_cpe_completely_right = 0 # number where we nailed all the CPES (just vendor/product)
    num_cpe_partially_right = 0 # number where we nailed some of them
    num_cpe_empty = 0 #num we couldn't figure out
    num_cpe_vendor_wrong = 0 #num we messed up
    num_cpe_completely_wrong = 0 #num we messed up
    num_errors = 0

    # comparisons
    #TODO compare comparison nodes somehow

    for line in reader:
        cve_id =line["CVE-ID"]
        try:
            p_cpe, i_cpe = json.loads(line["Provided cpe"])[0],  json.loads(line["Inferred cpe"])[0]
        except:
            traceback.print_exc()
            num_errors += 1
            continue
        #monkeypatch
        if len(i_cpe) == 0: 
            node = json.loads(line["Inferred Nodes"].replace("'",'"'))[0]
            if "cpe23Uri" in node:
                i_cpe.append(node["cpe23Uri"])

        # turn each into just the first parts of the cpe, ignoring more specific metrics like editions
        p_cpe, i_cpe = set(cpe_prefix(x) for x in p_cpe), set(cpe_prefix(x) for x in i_cpe)


        if len(p_cpe ^ i_cpe) == 0:
            num_cpe_completely_right += 1
        elif len(i_cpe) == 0 and len(p_cpe) > 0:
            print("EMPTY------------------------" + cve_id)
            print(p_cpe)
            print(i_cpe)
            print("EMPTY------------------------")
            num_cpe_empty += 1
        elif len(p_cpe - i_cpe) > 0 and len(i_cpe - p_cpe) == 0:
            # print("PARTIAL------------------------" + cve_id)
            # print(p_cpe)
            # print(i_cpe)
            # print("PARTIAL------------------------")
            num_cpe_partially_right +=1
        else:
            p2_cpe, i2_cpe = set(x.split(":")[-1] for x in p_cpe), set(x.split(":")[-1] for x in i_cpe)
            if(len(p2_cpe ^ i2_cpe) == 0):
                num_cpe_vendor_wrong += 1
                print("VENDOR WRONG------------------------" + cve_id)
                print(p_cpe)
                print(i_cpe)
                print("/VENDOR WRONG------------------------")
            else:
                print("WRONG------------------------" + cve_id)
                print(p_cpe)
                print(i_cpe)
                print("/WRONG------------------------")
                num_cpe_completely_wrong +=1




    print(f"Num correct:{num_cpe_completely_right}")
    print(f"Num partial:{num_cpe_partially_right}")
    print(f"Num empty:{num_cpe_empty}")
    print(f"Num vendor_only wrong:{num_cpe_vendor_wrong}")
    print(f"Num wrong:{num_cpe_completely_wrong}")
    print(f"Num errors:{num_errors}")
    total = num_cpe_completely_right + num_cpe_partially_right + num_cpe_empty + num_cpe_vendor_wrong + num_cpe_completely_wrong + num_errors
    print(f"total:{total}")