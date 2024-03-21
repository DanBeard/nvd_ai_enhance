import json
import time
import csv
import traceback
from langchain_community.document_loaders import WebBaseLoader
from enhance_utils import EnhanceUtils, CpeLookup, CveOrgLookup, MetaLog


# settings
file_to_enhance = "./NVD_DATA/nvdcve-1.1-recent.json"
#file_to_enhance = "./NVD_DATA/nvdcve-1.1-2023.json"
meta_info_output_file = "./stats-2023.csv" #write metainfo here for comparisons
delay_every_secs = 0 # delay between CVEs so we don't hit rate limits
overwrite_cves_with_cpes = True # set to true to overwrite cves with cpes that already exist. Good for comparison/testing/metrics but not for actual use
enhance_at_most = 10000000 # limit for testing. raise to very large value for real use
recalc_cpe_set = False # set to True to force a re-calc of Cpes

utils = EnhanceUtils(CpeLookup("./NVD_DATA/nvdcpematch-1.0.json", "./NVD_DATA/cpe_set.json", recalc_cpe_set),  CveOrgLookup("./cvelistv5-main.zip"))


print("Loading file to enhance:")
i=0
with open(meta_info_output_file, "w") as meta_out:
    meta_log = MetaLog(meta_out)
    meta_log.write_header()
    
    with open(file_to_enhance,"r") as f:
        j = json.load(f)
        num_items = len( j["CVE_Items"])
        print(f"Improving {num_items} items...")
        for cve in j["CVE_Items"]:
            try:
                cve_id = cve.get("cve",{}).get("CVE_data_meta",{}).get("ID","")
                
                if len(cve["configurations"]["nodes"]) > 0 and not overwrite_cves_with_cpes:
                    continue

                i = i + 1
                if i>enhance_at_most:
                    break
                
                desc_data = cve.get("cve",{}).get("description",{}).get("description_data", [])
                summary = None
                if len(desc_data) > 0:
                    summary = desc_data[0].get("value","")
                else:
                    continue

                #edge case ... rejected CVEs
                if summary.lower().startswith("rejected"):
                    print(cve_id + " was rejected -- skipping")
                    continue

                refs = cve.get("cve",{}).get("references",{}).get("reference_data",[])
                old_nodes = cve["configurations"]["nodes"]
                print(cve_id)
                meta_info = utils.get_enhanced_nodes(cve_id, summary)
                if meta_info is None:
                    continue
                
                cve["configurations"]["nodes"] = [meta_info.inferred_nodes]           
                meta_log.write_meta_info(cve_id, old_nodes, meta_info)
                time.sleep(delay_every_secs)
            except Exception as e:
                print("!!!!!!!!!!! EXCEPTION! ")
                traceback.print_exc()
                print("Above from CVE="+str(cve_id))
                #raise e # disable when not debugging an exception
                # move on so we don't crash everything

        with open(file_to_enhance+".enhanced.json", 'w') as fpout:
            json.dump(j, fp=fpout)

        
