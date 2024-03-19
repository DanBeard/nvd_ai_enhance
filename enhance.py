import json
import time
import textdistance
import csv
import traceback
from langchain_community.document_loaders import WebBaseLoader
import requests
#from bs4 import BeautifulSoup
from comparison_parser import turn_alg_into_nodes

# settings
#file_to_enhance = "./NVD_DATA/nvdcve-1.1-recent.json"
file_to_enhance = "./NVD_DATA/nvdcve-1.1-2023.json"
meta_info_output_file = "./stats-2023.csv" #write metainfo here for comparisons
delay_every_secs = 3 # delay between CVEs so we don't hit rate limits
overwrite_cves_with_cpes = True # set to true to overwrite cves with cpes that already exist. Good for comparison/testing/metrics but not for actual use
enhance_at_most = 1000 # limit for testing. raise to very large value for real use
recalc_cpe_set = False # set to True to force a re-calc of Cpes

from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain.globals import set_llm_cache
from langchain.cache import SQLiteCache
from langchain_community.document_loaders import PyPDFLoader
import langchain
langchain.verbose = True

set_llm_cache(SQLiteCache(database_path=".langchain.db"))

#chat = ChatAnthropic(temperature=0, model_name="claude-3-haiku-20240307")
chat = ChatAnthropic(temperature=0, model_name="claude-3-sonnet-20240229")

def enhance_cpe_info(summary, refs):
   
    # TODO: figure out when to use ref info. the HTML adds a lot of needles garbage. Seems to actually get worse results in many cases.
    #ref_info = filter_and_grab_ref_data(refs)
    
    system = (
"""Translate CVE descriptions into short algebraic expressions contained in JSON form. Given the description provided, generate a mathematical statement that will determine if a product is vulnerable based on it's version.
Return only the JSON object and not any description or configuration information. If no version information is available, then return en empty json object. Here are some examples:
<example>
<description>
AUTER Controls Nova 200–220 Series with firmware version 3.3-006 and prior and BACnetstac version 4.2.1 and prior have only FTP and Telnet available for device management. Any sensitive information communicated through these protocols, such as credentials, is sent in cleartext. An attacker could obtain sensitive information such as user credentials to gain access to the system. 
</description>
result: {"SAUTER Controls Nova 200-220 Series": "firmware < 3.3-007", "BACnetstac": "version <= 4.2.1"}
<example>

<example>
<description>
An issue has been discovered in GitLab CE/EE affecting all versions starting from 11.4 prior to 15.5.7, 15.6 prior to 15.6.4, and 15.7 prior to 15.7.2. GitLab Pages allows redirection to arbitrary protocols.
</description>
result: :{"gitlab": "(version >= 11.4 && version < 15.5.7) || (version >= 15.6 && version < 15.6.4) || (version >= 15.7 && version < 15.7.2)"}
<example>

<example>
<description>
A local file deletion vulnerability in Palo Alto Networks PAN-OS software enables an authenticated administrator to delete files from the local file system with elevated privileges.
</description>
result: :{}
<example>
""".replace('{', '{{').replace('}', '}}')

    )
    human = "<description>\n{summary}\n</description>\n result:{{" #\n<reference_info>{ref_info}</reference_info>"
    prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])

    chain = prompt | chat
    result = chain.invoke(
        {
            "summary": summary , 
            #"ref_info": ref_info
        }
    )

    try:
        info = json.loads(result.content)
    except json.decoder.JSONDecodeError as e:
        print("Decode error:"+result.content)
        return None, None
    
    #print(info)
    product_names = info.keys()
    if len(product_names) == 0:
        print("NO product name in:" + json.dumps(info))
        return None, None
    else:
        print(info)
    
    nodes = []
    meta_info = []
    for product_name in product_names:
        # Ok, we have the product name and crieria, let's lookup a cpe and contrauct a json object around it
        system = (
"""
You are a helpful AI bot programmed to lookup CPEs from product names
Given the supplied product name return the CPE string that represents that product. Return only the CPE string and no explanation
If there is not enough information to generate a result return an empty string
"""
        )
        human = "<product>{product_name}</product>"
        #Pimcore's Admin Classic Bundle
        prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])
        chain = prompt | chat
        result = chain.invoke(
            {
                "product_name": product_name
            }
        )

        #print(result)
        cpe = result.content
        if len(cpe) == 0:
            continue
        
        # massage from old CPE string to new cpeString
        if cpe.startswith("cpe:/a"):
            cpe_split =  = cpe.split(":")
            if len(cpe_split) >= 4:
                cpe = f"cpe:2.3:a:{cpe_split[0]}:{cpe_split[1]}:-:*:*:*:*:*:*:*"
    
        condition =  info.get(product_name) #info.get("expression", None) or info.get("condition", None) or info.get("version", None)
        meta_info.append({"cpe": cpe, "condition": condition, "product_name":product_name, "cve_summary": summary,"meta": json.dumps(info)})

    
        node = create_nvd_node(cpe, condition, product_name=product_name)
        nodes.append(node)
    
    if len(nodes) == 0:
        return None, None
    elif len(nodes) == 1:
        return nodes[0], meta_info
    else:
        # combine into one node with children
        parent_node = {
                    "operator" : "OR",
                    "children" : nodes ,
                    "cpe_match" : [],
                    "ae:confidence":nodes[0].get("ae:confidence","")
                }
        return parent_node, meta_info

def filter_and_grab_ref_data(refs):
    """
    filter and grab the ref data. Try to only include text based advisory data and not like patches and stuff
    TODO: different loaders for PDFs
    """

    def is_good_ref(ref):
        url, name = ref["url"], ref["name"]
        if url.endswith(".sh") or url.endswith(".patch"):
            return False
        if "changeset" in url or "blob" in url:
            return False
        if "advisories" in url or "support" in url or "bulletin" in url:
            return True
        if "advisory" in name:
            return True
        # assume bad for now. Maybe we make this better and assume true?
        return False

    try: 
        filtered = [x for x in refs if is_good_ref(x)]
    
        if len(filtered) == 0:
            return ""
        
        # Just pick the first good one for now. Maybe we provde for context to larger models later
        ref = filtered[0]
        loader = WebBaseLoader(ref["url"])
        return loader.load()[0].page_content
        #html_doc = requests.get(ref["url"])
        #soup = BeautifulSoup(html_doc.text, 'html.parser')
    except Exception as e:
        print("Error in grabbing ref info " + str(e))
        return ""
     

       

def does_ai_think_this_matches(product_name, nearest_cpe):
    system = (
        "you are a helpful AI bot that checks if CPEs are valid. does the provided CPE match the provided product name? answer with a simple yes or no:" 
    )
    human = "<cpe>{cpe}</cpe>\n<product_name>{product_name}</product_name>"
    prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])

    chain = prompt | chat
    result = chain.invoke(
        {
            "cpe": nearest_cpe , 
            "product_name": product_name
        }
    )

    print(F"asking AI does {nearest_cpe} == {product_name}")
    print(result.content)
    return result.content.strip().lower() == "yes"

def create_nvd_node(cpe_string, condition, product_name):
    
    nodes = []
    confidence = "none"

    for cpe in cpe_string.split("\n"):
       # massage cpe string
        if cpe_to_cpe_prefix(cpe) in vendor_product_set:
            confidence = "high"
            #print(f"{cpe} - high")
        else:
            dist, nearest_cpe = find_closest_cpe_prefixs(cpe_to_cpe_prefix(cpe))[0]
            # TODO this is just a gut number. run some tests on it and fine tune
            # But we need a simple catch that avoid an LLM call if it's REALLLLY close or REALLY FAR. No need to spend money if it's obvious
            nearest_cpe_str = f"cpe:2.3:a:{nearest_cpe}:-:*:*:*:*:*:*:*"  # TODO include :a: vs :o: vs :h: in cpe set
            if dist < 0.067 or (dist <0.33 and does_ai_think_this_matches(product_name, nearest_cpe_str)):
                #print(f"{cpe} - medium :/ {nearest_cpe} at {dist}")
                confidence = "medium"
                # replace with the one we found
                cpe = nearest_cpe_str
            else:
                pass
                #print(f"{cpe} - none :/ closest was {nearest_cpe} at {dist} ")
       

        # some basic massaging of the LLM output here:
        if condition is not None:
            condition = condition.strip()
            # base case
            if " " not in condition:
                # then we put it in the cpe
                cpe_split = cpe.split(":")
                if(len(cpe_split) < 10):
                    cpe_split = cpe_split + ['*'] * (12 - len(cpe_split))
                cpe_split[5] = condition
                cpe = ":".join(cpe_split)
                
                match =  {
                    "vulnerable" : True,
                    "cpe_name" : [ ],
                    "cpe23Uri": cpe
                    }
                
                nodes.append({
                    "operator" : "OR",
                    "children" : [ ],
                    "cpe_match" : [match]
                })

            else:
                # sanity check. If it just starts with a comparitor prepend with a word so it's parsed propery by our parser
                if(condition.startswith("<") or condition.startswith(">") or condition.startswith("=")):
                    condition = "v " + condition
                nodes.append(turn_alg_into_nodes(condition, cpe))
                
    if len(nodes) == 1:
        result = nodes[0]
        result["ae:confidence"] = confidence
        return result
    elif len(nodes) == 0:
        return None
    else:
        return {
                    "operator" : "OR",
                    "children" : nodes ,
                    "cpe_match" : [],
                    "ae:confidence":confidence
                }


def node_to_cpes(node):
    child_cpes = []
    # recursively grab CPEs in children nodes
    for child in node.get("children", []):
        child_cpes.extend(node_to_cpes(child))

    result = [x.get("cpe23Uri","") for x in node.get("cpe_match",[])]
    result.extend(child_cpes)
    return result

def cpe_to_cpe_prefix(cpe):
    return ":".join(cpe.split(":")[3:5])

def find_closest_cpe_prefixs(cpe_prefix, max_match=3):
    results = []
    cmp = textdistance.JaroWinkler()
    cpe_prefix = cpe_prefix[::-1] # reverse Jaro winkler to prioritize product name
    for x in vendor_product_set:
        if len(results) < max_match:
            results.append([cmp.distance(cpe_prefix,x), x])
        else:
            dist = cmp.distance(cpe_prefix,x)
            for y in results:
                if y[0] > dist:
                    y[0] = dist
                    y[1] = x
                    break

    # reverse back so we don't get CPEs backwards
    return [(x[0], x[1][::-1]) for x in results]



# load cpe_lookup
print("Loading cpe lookup")
vendor_product_set = set()

if recalc_cpe_set: # TODO Or of cached doesnt exist
    new_vendor_product_set = set()
    with open("./NVD_DATA/nvdcpematch-1.0.json", "r") as f:
        j = json.load(f)["matches"]
        for m in j:
            cpe_prefix = cpe_to_cpe_prefix(m["cpe23Uri"])
            new_vendor_product_set.add(cpe_prefix)
    with open("./NVD_DATA/cpe_set.json", "w") as f:
        json.dump([x for x in new_vendor_product_set], fp=f)
        del new_vendor_product_set
# load the cpe set from our cache
with open("./NVD_DATA/cpe_set.json", "r") as f:
    j = json.load(f)
    for cpe_prefix in j:
        cpe_prefix = cpe_prefix[::-1] # reverse Jaro winkler to prioritize product name
        vendor_product_set.add(cpe_prefix)

print("Loading file to enhance:")
i=0
with open(meta_info_output_file, "w") as meta_out:
    meta_w = csv.writer(meta_out)
    meta_w.writerow(["CVE-ID","Summary", "Provided Nodes", "Provided cpe", "Inferred cpe", "Inferred Product Name",  "Inferred Nodes", "Inferred Nodes Confidence", "LLM generated condition string"])
    

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

                refs = cve.get("cve",{}).get("references",{}).get("reference_data",[])
                old_nodes = cve["configurations"]["nodes"]
                print(cve_id)
                node, meta_info = enhance_cpe_info(summary, refs)
                if node is None:
                    if meta_info is None:
                        meta_info = [{}]
                    #print("Node returend was None :( )")
                    meta_w.writerow([cve_id, summary,json.dumps(old_nodes),json.dumps([node_to_cpes(x) for x in old_nodes]),"",meta_info[0].get("product_name",""), "", "", meta_info[0].get("condition","")])
                    continue
                
                cve["configurations"]["nodes"] = [node]
                
               
                confidence = ""
                if len(node.get("cpe_match",[])) > 0:
                    confidence = node.get("cpe_match",[])[0].get("ae:confidence","")
                
                #print(meta_info.get("condition",""))
                #print(json.dumps(node))
                print(node)
                meta_w.writerow([cve_id, summary,json.dumps(old_nodes),json.dumps([node_to_cpes(x) for x in old_nodes]),json.dumps([node_to_cpes(node)]),meta_info[0].get("product_name",""),[node], confidence, meta_info[0].get("condition","")])
                time.sleep(delay_every_secs)
            except Exception as e:
                print("!!!!!!!!!!! EXCEPTION! ")
                traceback.print_exc()
                print("Above from CVE="+str(cve_id))
                #raise e # disable when not debugging an exception
                # move on so we don't crash everything

        with open(file_to_enhance+".enhanced.json", 'w') as fpout:
            json.dump(j, fp=fpout)

        
