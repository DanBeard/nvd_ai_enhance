import csv
import json 

stats_filename = "./stats-2023-bak-1000-noref.csv"


def cpe_prefix(cpe):
    return ":".join(cpe.split(":")[0:5])


with open(stats_filename,'r') as sfile:
    reader = csv.DictReader(sfile)

    # stats
    num_cpe_completely_right = 0 # number where we nailed all the CPES (just vendor/product)
    num_cpe_partially_right = 0 # number where we nailed some of them
    num_cpe_empty = 0 #num we couldn't figure out
    num_cpe_wrong = 0 #num we messed up

    # comparisons
    #TODO compare comparison nodes somehow

    for line in reader:
        cve_id =line["CVE-ID"]
        p_cpe, i_cpe = json.loads(line["Provided cpe"])[0],  json.loads(line["Inferred cpe"])[0]
        
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
            print("PARTIAL------------------------" + cve_id)
            print(p_cpe)
            print(i_cpe)
            print("PARTIAL------------------------")
            num_cpe_partially_right +=1
        else:
            print("WRONG------------------------" + cve_id)
            print(p_cpe)
            print(i_cpe)
            print("/WRONG------------------------")
            num_cpe_wrong +=1




    print(f"Num correct:{num_cpe_completely_right}")
    print(f"Num partial:{num_cpe_partially_right}")
    print(f"Num empty:{num_cpe_wrong}")
    print(f"Num wrong:{num_cpe_wrong}")