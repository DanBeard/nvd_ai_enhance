import json
import textdistance
import zipfile
import csv
from dataclasses import dataclass
from comparison_parser import turn_alg_into_nodes
from enhance_llm_utils import LLM_Utils

@dataclass
class MatchMetadata():
   inferred_product_name : str
   inferred_nodes : dict
   confidence: str
   condition: str 
   llm_used:bool


class CpeLookup():  # "./NVD_DATA/nvdcpematch-1.0.json" "./NVD_DATA/cpe_set.json"
    def __init__(self, nvdcpematch_file, cache_file, overwrite_cache):
        print("Loading cpe lookup")
        self.vendor_product_set = set()
        if overwrite_cache: # TODO Or of cached doesnt exist
            new_vendor_product_set = set()
            with open(nvdcpematch_file, "r") as f:
                j = json.load(f)["matches"]
                for m in j:
                    cpe_prefix = self.cpe_to_cpe_prefix(m["cpe23Uri"])
                    new_vendor_product_set.add(cpe_prefix)
            with open(cache_file, "w") as f:
                json.dump([x for x in new_vendor_product_set], fp=f)
                del new_vendor_product_set
        
        # load the cpe set from our cache
        with open(cache_file, "r") as f:
            j = json.load(f)
            for cpe_prefix in j:
                cpe_prefix = cpe_prefix[::-1] # reverse Jaro winkler to prioritize product name
                self.vendor_product_set.add(cpe_prefix)
            print("/Loading cpe lookup")
                
    
    @staticmethod
    def cpe_to_cpe_prefix(cpe):
        return ":".join(cpe.split(":")[3:5])
    
    def is_valid_cpe(self, cpe):
        return self.cpe_to_cpe_prefix(cpe) in self.vendor_product_set
    
    def find_closest_cpe(self, cpe, max_match=3):
        results = []
        cmp = textdistance.JaroWinkler()
        cpe_prefix = self.cpe_to_cpe_prefix(cpe)[::-1] # reverse Jaro winkler to prioritize product name
        for x in self.vendor_product_set:
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
        return [(x[0], f"cpe:2.3:a:{x[1][::-1]}:-:*:*:*:*:*:*:*") for x in results]
    
class CveOrgLookup():
    
    def __init__(self,zip_loc):
        self._zip_loc = zip_loc
        self._zip = zipfile.ZipFile(zip_loc)

    def get_cve(self, cve_id):
        cve_split = cve_id.split("-")
        _, year, idx = cve_split
        #do the weird xxx folder thing
        idx = idx[0:-3] + "xxx"
        path = f"cvelistV5-main/cves/{year}/{idx}/{cve_id}.json"
        try:
            return json.loads(self._zip.read(path))
        except KeyError:
            return None
        

class EnhanceUtils():
    def __init__(self, cpe_lookup: CpeLookup, cve_lookup: CveOrgLookup):
        self._llm = LLM_Utils()
        self._cpe_lookup = cpe_lookup
        self._cve_lookup = cve_lookup

    @staticmethod
    def _massage_cpe(cpe):
        """
        massage bad cpes to be 2.3 format
        """
         # massage from old CPE string to new cpeString
        if cpe.startswith("cpe:/a"):
            cpe_split = cpe.split(":")
            if len(cpe_split) >= 4:
                cpe = f"cpe:2.3:a:{cpe_split[0]}:{cpe_split[1]}:-:*:*:*:*:*:*:*"

        return cpe
    
    @staticmethod
    def _wrap_node_list(nodes):
        """
        wrap nodes if more than one in an OR parent node
        """
        if len(nodes) == 0:
            return None
        elif len(nodes) == 1:
            return nodes[0]
        else:
            # combine into one node with children
            parent_node = {
                        "operator" : "OR",
                        "children" : nodes ,
                        "cpe_match" : [],
                    }
            return parent_node
        

    def get_cpe_from_product_name(self, vendor_name, product_name):
        confidence = "none"
        cpe = self._llm.lookup_cpes(vendor_name,product_name)[0]
        if self._cpe_lookup.is_valid_cpe(cpe):
            confidence = "high"
            #print(f"{cpe} - high")
        else:
            dist, nearest_cpe = self._cpe_lookup.find_closest_cpe(cpe)[0]
            # TODO this is just a gut number. run some tests on it and fine tune
            # But we need a simple catch that avoid an LLM call if it's REALLLLY close or REALLY FAR. No need to spend money if it's obvious
        
            if dist < 0.067 or (dist <0.33 and self._llm.does_ai_think_this_matches(product_name, nearest_cpe)):
                #print(f"{cpe} - medium :/ {nearest_cpe} at {dist}")
                confidence = "medium"
                # replace with the one we found
                cpe = nearest_cpe
        
        return cpe, confidence

    def get_enhanced_nodes(self, cve_id, summary) -> MatchMetadata:
        cve_data = self._cve_lookup.get_cve(cve_id)

        try:
            # try and use CVE.org data first
            cve_result = self._create_nvd_node_from_cve_data(cve_data)
            if cve_result is not None:
                return cve_result
        except Exception as e:
            print(f"Got error with CVE data parsing -- trying LLM backup. Error was -> {e}")
            
        
        # if that didn't work try with the LLM
        llm_result = self._create_nvd_node_from_llm_output(summary)
        return llm_result
        

    def _create_nvd_node_from_cve_data(self, cve_data) -> MatchMetadata:
        if cve_data is None:
            return None
        
        affected_data = cve_data.get("containers",{}).get("cna", {}).get("affected", [])

        nodes = []
        for a in affected_data:
            vendor, product = a.get("vendor", None), a.get("product", None)
            if product is None:
                continue

            versions =  a.get("versions", [])
            # special case. If there's only one version and it's unaffected, then skip whole product
            if len(versions) == 1 and versions[0].get("status", "unknown") == "unaffected":
                continue
            
            cpe, confidence = self.get_cpe_from_product_name(vendor,product)
           
            default = a.get("defaultStatus", "unaffected")
            if default == "affected":
                print(cve_data["cveMetadata"]["cveId"] + " has default affected. O.o")
                return None #TODO: eject to LLM until we figure out how to handle this
            
            expression = []
            
            for v in versions:
                status = v.get("status", "unknown")
                order_op = "<" if status == "affected" else "<" # swap comparison depnding on affected or not
                exact_op = "==" if status == "affected" else "!="
                less_than = v.get("lessThan", None)
                less_than_eq = v.get("lessThanOrEqual", None)
                if less_than_eq is not None: # save some logic by reusing less_than
                    order_op += "="
                    less_than = less_than_eq

                version = v.get("version", None)
                if version is not None:
                    version = version.strip().replace(" ","")

                if less_than is not None:
                    v_str = ""
                    if version is not None and version.strip() != "*":  # for versions starting at version swap order
                        v_str = "v " + ("> " if order_op.startswith("<") else "< ") + version + " && "

                    lt_list = []
                    for ln in less_than.split(","):
                        ln = ln.strip().replace(" ","").replace("*","0")
                        lt_list.append(f" v {order_op} {ln} ")

                    for less_than_str in lt_list:
                        expression.append(f"( {v_str} {less_than_str} )")
                elif version is not None:
                    # only add affected versions here
                    if status == "affected":
                        expression.append(f"(v {exact_op} {version})")

            condition = " || ".join(expression)
            nodes.append( nodes.append(turn_alg_into_nodes(condition, cpe)))
        
        return MatchMetadata(inferred_nodes=self._wrap_node_list(nodes),
                    inferred_product_name=product,
                    condition=condition,
                    confidence=confidence,
                    llm_used=False
                    )



    def _create_nvd_node_from_llm_output(self, summary) -> MatchMetadata:
        """
        internal method: use the LLM to get the data
        """
        nodes = []
        info = self._llm.get_cpe_info(summary)
        print("LLM:"+summary)
        # info is a dict where the key is the product name and the value is the condition
        product_name = ""
        confidence = "None"

        for product_name in info.keys():
            condition = info[product_name]

            cpe, confidence = self.get_cpe_from_product_name(None,product_name)
           
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

        return MatchMetadata(inferred_nodes=self._wrap_node_list(nodes),
                      inferred_product_name=product_name,
                      condition=condition,
                      confidence=confidence,
                      llm_used=True
                      )


class MetaLog():
    def __init__(self,meta_out) -> None:
        self._meta_out = meta_out
        self._w = csv.writer(meta_out)

    def write_header(self):
        self._w.writerow(["CVE-ID", "Provided Nodes", "Provided cpe",
                           "Inferred cpe", "Inferred Product Name",  "Inferred Nodes", "Inferred Nodes Confidence", "LLM generated condition string",
                           "LLM summary generation used"])

    def write_meta_info(self, cve_id: str, old_nodes: dict, info: MatchMetadata):

        self._w.writerow([cve_id, json.dumps(old_nodes), json.dumps([self.node_to_cpes(x) for x in old_nodes]),
                          json.dumps([self.node_to_cpes(info.inferred_nodes)]), info.inferred_product_name, json.dumps(info.inferred_nodes), info.confidence, info.confidence,
                          info.llm_used])


    def node_to_cpes(self, node):
        if node is None:
            return []
        
        child_cpes = []
        # recursively grab CPEs in children nodes
        for child in node.get("children", []):
            child_cpes.extend(self.node_to_cpes(child))

        result = [x.get("cpe23Uri","") for x in node.get("cpe_match",[])]
        result.extend(child_cpes)
        return result

