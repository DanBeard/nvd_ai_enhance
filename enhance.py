import json
import time
import textdistance
import csv

# settings
file_to_enhance = "./NVD_DATA/nvdcve-1.1-recent.json"
#file_to_enhance = "./NVD_DATA/nvdcve-1.1-2023.json"
meta_info_output_file = "./stats-recent.csv" #write metainfo here for comparisons
delay_every_secs = 0 # delay between CVEs so we don't hit rate limits
overwrite_cves_with_cpes = True # set to true to overwrite cves with cpes that already exist. Good for comparison/testing/metrics but not for actual use
enhance_at_most = 100000000 # limit for testing. raise to very large value for real use

from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain.globals import set_llm_cache
from langchain.cache import SQLiteCache

set_llm_cache(SQLiteCache(database_path=".langchain.db"))

chat = ChatAnthropic(temperature=0, model_name="claude-3-haiku-20240307")

def enhance_cpe_info(summary):
   
    system = (
        "You are a helpful AI bot programmed to translate CVE descriptions into short algebraic expressions contained in JSON form." +\
            "Given the description provided, generate a mathematical statement that will determine if a product meets the description (for example: \"openssl < 3.0\"). Include the product name in the result. Don't include the description in the result " + \
            "If there is not enough information to generate an algebreic result then just return an empty JSON object" # todo: test if it can't be determined?
    )
    human = "<description>{summary}</description>"
    prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])

    chain = prompt | chat
    result = chain.invoke(
        {
            "summary": summary  
        }
    )

    try:
        info = json.loads(result.content)
    except json.decoder.JSONDecodeError as e:
        print("Decode error:"+result.content)
        return None, None
    
    #print(info)
    product_name = info.get("product", None)
    if product_name is None:
        return None, None
    # Ok, we have the product name and crieria, let's lookup a cpe and contrauct a json object around it
    system = (
        "You are a helpful AI bot programmed to lookup CPEs from product names" +\
            "Given the supplied product name return the CPE string that represents that product. Return only the CPE string and no explanation " + \
            "If there is not enough information to generate a result return an empty string" # todo: test if it can't be determined?
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
        return None, None
    
    #TODO turn this into something like the NVD would
    condition =  info.get("expression", None) or info.get("condition", None) or info.get("version", None)
    meta_info = {"cpe": cpe, "condition": condition, "product_name":product_name, "cve_summary": summary,"meta": json.dumps(info)}
    #print(meta_info)
    
    return create_nvd_node(cpe, condition, product_name=product_name), meta_info

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

    matches = []
    for cpe in cpe_string.split("\n"):
        match =  {
            "vulnerable" : True,
            "cpe_name" : [ ],
            "ae:confidence": "none"
            }
        # some basic massaging of the LLM output here:
        if condition is not None:
            condition = condition.strip()
            if condition.startswith("version "):
                condition = condition[8:].strip()

            if condition.startswith("<"):
                match["versionEndIncluding"] = condition[1:].strip().split(" ")[0]
            elif condition.startswith(">"):
                match["versionStartIncluding"] = condition[1:].strip().split(" ")[0]
            elif " " not in condition:
                # then we put it in the cpe
                cpe_split = cpe.split(":")
                if(len(cpe_split) < 10):
                    cpe_split = cpe_split + ['*'] * (12 - len(cpe_split))
                cpe_split[5] = condition
                cpe = ":".join(cpe_split)


        # set cpe confidence
        if cpe_to_cpe_prefix(cpe) in vendor_product_set:
            match["ae:confidence"] = "high"
            print(f"{cpe} - high")

        else:
            dist, nearest_cpe = find_closest_cpe_prefixs(cpe_to_cpe_prefix(cpe))[0]
            # TODO this is just a gut number. run some tests on it and fine tune
            # But we need a simple catch that avoid an LLM call if it's REALLLLY close or REALLY FAR. No need to spend money if it's obvious
            if dist < 0.067 or (dist <0.14 and does_ai_think_this_matches(product_name, f"cpe:2.3:a:{nearest_cpe}:-:*:*:*:*:*:*:*")):
                print(f"{cpe} - medium :/ {nearest_cpe} at {dist}")
                match["ae:confidence"] = "medium"
                # replace with the one we found
                cpe_split = cpe.split(":")
                ncpe_split = nearest_cpe.split(":")
                cpe_split[3], cpe_split[4] = ncpe_split[0], ncpe_split[1]
                cpe = ":".join(cpe_split)
            else:
                print(f"{cpe} - none :/ closest was {nearest_cpe} at {dist} ")
                

        match["cpe23Uri"] = cpe 
        matches.append(match)

    return {
        "operator" : "OR",
        "children" : [ ],
        "cpe_match" : matches
    }

def node_to_cpes(node):
    return [x.get("cpe23Uri","") for x in node.get("cpe_match",[])]

def cpe_to_cpe_prefix(cpe):
    return ":".join(cpe.split(":")[3:5])

def find_closest_cpe_prefixs(cpe_prefix, max_match=3):
    results = []
    cmp = textdistance.JaroWinkler()
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
    return results



# load cpe_lookup
print("Loading cpe lookup")
vendor_product_set = set()

with open("./NVD_DATA/nvdcpematch-1.0.json", "r") as f:
    j = json.load(f)["matches"]
    for m in j:
        cpe_prefix = cpe_to_cpe_prefix(m["cpe23Uri"])
        #print(cpe_prefix)
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
                    break;
                
                desc_data = cve.get("cve",{}).get("description",{}).get("description_data", [])
                summary = None
                if len(desc_data) > 0:
                    summary = desc_data[0].get("value","")
                else:
                    continue
                node, meta_info = enhance_cpe_info(summary)
                if node is None:
                    print("Node returend was None :( )")
                    continue
                old_nodes = cve["configurations"]["nodes"]
                cve["configurations"]["nodes"] = [node]
                
               
                confidence = ""
                if len(node.get("cpe_match",[])) > 0:
                    confidence = node.get("cpe_match",[])[0].get("ae:confidence","")
                
                print(cve_id)
                meta_w.writerow([cve_id, summary,json.dumps(old_nodes),json.dumps([node_to_cpes(x) for x in old_nodes]),json.dumps([node_to_cpes(node)]),meta_info.get("product_name",""),[node], confidence, meta_info.get("condition","")])
                time.sleep(delay_every_secs)
            except Exception as e:
                print("!!!!!!!!!!! EXCEPTION! ")
                print(e)
                #raise e # disable when not debugging an exception
                # move on so we don't crash everything

        with open(file_to_enhance+".enhanced.json", 'w') as fpout:
            json.dump(j, fp=fpout)

        

# summaries = [
#     #"A vulnerability has been found in Guangdong Pythagorean OA Office System up to 4.50.31 and classified as problematic. Affected by this vulnerability is an unknown functionality of the component Schedule Handler. The manipulation of the argument description leads to cross site scripting. The attack can be launched remotely. The exploit has been disclosed to the public and may be used. The associated identifier of this vulnerability is VDB-230467.",
#     "JFinal CMS v5.1.0 was discovered to contain a remote code execution (RCE) vulnerability via the ActionEnter function.",
#      #"TOTOLINK X2000R before V1.0.0-B20231213.1013 contains a Stored Cross-site scripting (XSS) vulnerability in MAC Filtering under the Firewall Page.",
#      #"Sciener locks' firmware update mechanism do not authenticate or validate firmware updates if passed to the lock through the Bluetooth Low Energy service. A challenge request can be sent to the lock with a command to prepare for an update, rather than an unlock request, allowing an attacker to compromise the device.",
#     #  "The unlockKey character in a lock using Sciener firmware can be brute forced through repeated challenge requests, compromising the locks integrity.",
#     #"Cross-Site Request Forgery (CSRF) vulnerability in Cozmoslabs Paid Member Subscriptions.This issue affects Paid Member Subscriptions: from n/a through 2.10.4.\n\n",
#     #"A vulnerability classified as critical has been found in boyiddha Automated-Mess-Management-System 1.0. Affected is an unknown function of the file /member/view.php. The manipulation of the argument date leads to sql injection. It is possible to launch the attack remotely. The exploit has been disclosed to the public and may be used. VDB-256050 is the identifier assigned to this vulnerability. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.",
       

# ]

# import time
# # summary = "Pimcore's Admin Classic Bundle provides a backend user interface for Pimcore. Prior to version 1.3.3, an attacker can create, delete etc. tags without having the permission to do so. A fix is available in version 1.3.3. As a workaround, one may apply the patch manually."
# for s in summaries:  
#     print(enhance_cpe_info(s))
#     time.sleep(20)