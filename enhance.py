import json
import time
import csv
import traceback
from langchain_community.document_loaders import WebBaseLoader
from enhance_utils import EnhanceUtils, CpeLookup, CveOrgLookup, MetaLog


# settings
#file_to_enhance = "./NVD_DATA/nvdcve-1.1-recent.json"
file_to_enhance = "./NVD_DATA/nvdcve-1.1-2023.json"
meta_info_output_file = "./stats-2023.csv" #write metainfo here for comparisons
delay_every_secs = 1 # delay between CVEs so we don't hit rate limits
overwrite_cves_with_cpes = True # set to true to overwrite cves with cpes that already exist. Good for comparison/testing/metrics but not for actual use
enhance_at_most = 1000 # limit for testing. raise to very large value for real use
recalc_cpe_set = False # set to True to force a re-calc of Cpes

utils = EnhanceUtils(CpeLookup("./NVD_DATA/nvdcpematch-1.0.json", "./NVD_DATA/cpe_set.json", recalc_cpe_set),  CveOrgLookup("./cvelistv5-main.zip"))

# def enhance_cpe_info(summary, refs):
   
#     # TODO: figure out when to use ref info. the HTML adds a lot of needles garbage. Seems to actually get worse results in many cases.
#     #ref_info = filter_and_grab_ref_data(refs)
    
   
    
#     #print(info)
#     product_names = info.keys()
#     if len(product_names) == 0:
#         print("NO product name in:" + json.dumps(info))
#         return None, None
#     else:
#         print(info)
    
#     nodes = []
#     meta_info = []
#     for product_name in product_names:
#         # Ok, we have the product name and crieria, let's lookup a cpe and contrauct a json object around it
        
#         if len(cpe) == 0:
#             continue
        
#         # massage from old CPE string to new cpeString
#         if cpe.startswith("cpe:/a"):
#             cpe_split = cpe.split(":")
#             if len(cpe_split) >= 4:
#                 cpe = f"cpe:2.3:a:{cpe_split[0]}:{cpe_split[1]}:-:*:*:*:*:*:*:*"
    
#         condition =  info.get(product_name) #info.get("expression", None) or info.get("condition", None) or info.get("version", None)
#         meta_info.append({"cpe": cpe, "condition": condition, "product_name":product_name, "cve_summary": summary,"meta": json.dumps(info)})

    
#         node = create_nvd_node(cpe, condition, product_name=product_name)
#         nodes.append(node)
    
#     if len(nodes) == 0:
#         return None, None
#     elif len(nodes) == 1:
#         return nodes[0], meta_info
#     else:
#         # combine into one node with children
#         parent_node = {
#                     "operator" : "OR",
#                     "children" : nodes ,
#                     "cpe_match" : [],
#                     "ae:confidence":nodes[0].get("ae:confidence","")
#                 }
#         return parent_node, meta_info

# def filter_and_grab_ref_data(refs):
#     """
#     filter and grab the ref data. Try to only include text based advisory data and not like patches and stuff
#     TODO: different loaders for PDFs
#     """

#     def is_good_ref(ref):
#         url, name = ref["url"], ref["name"]
#         if url.endswith(".sh") or url.endswith(".patch"):
#             return False
#         if "changeset" in url or "blob" in url:
#             return False
#         if "advisories" in url or "support" in url or "bulletin" in url:
#             return True
#         if "advisory" in name:
#             return True
#         # assume bad for now. Maybe we make this better and assume true?
#         return False

#     try: 
#         filtered = [x for x in refs if is_good_ref(x)]
    
#         if len(filtered) == 0:
#             return ""
        
#         # Just pick the first good one for now. Maybe we provde for context to larger models later
#         ref = filtered[0]
#         loader = WebBaseLoader(ref["url"])
#         return loader.load()[0].page_content
#         #html_doc = requests.get(ref["url"])
#         #soup = BeautifulSoup(html_doc.text, 'html.parser')
#     except Exception as e:
#         print("Error in grabbing ref info " + str(e))
#         return ""
     

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

        
