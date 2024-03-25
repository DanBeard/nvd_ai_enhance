"""
Goal is to generate a huge dict that maps from vendor -> product -> cpe
"""
import json


#cveorg_lookup_File = CveOrgLookup("./NVD_DATA/cvelistV5-main.zip")


nvdcve_file_names = ["./NVD_DATA/nvdcve-1.1-2023.json", "./NVD_DATA/nvdcve-1.1-2022.json", "./NVD_DATA/nvdcve-1.1-2021.json"]
output_file_name = "./NVD_DATA/cveorg_to_cpe.json"

def nvd_node_to_cpes(node):
    if node is None:
        return []

    child_cpes = []
    # recursively grab CPEs in children nodes
    for child in node.get("children", []):
        child_cpes.extend(nvd_node_to_cpes(child))

    result = [x.get("cpe23Uri", "") for x in node.get("cpe_match",[])]
    result.extend(child_cpes)
    return result


def build_cveorg_to_cpe_lookup(cveorg_lookup):
    from enhance_utils import CpeLookup
    result_lookup = {}
    no_info_list = []

    for nvdcve_file_name in nvdcve_file_names:
        with open(nvdcve_file_name, "r") as nvd_fin:
            nvd_cves = json.load(nvd_fin)

            for nvdcve in nvd_cves["CVE_Items"]:
                # get NVD data
                cve_id = nvdcve.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                refs = nvdcve.get("cve", {}).get("references", {}).get("reference_data",[])
                cpes = set()
                for node in nvdcve["configurations"]["nodes"]:
                    for cpe in nvd_node_to_cpes(node):
                        cpes.add(CpeLookup.cpe_to_cpe_prefix(cpe))

                # get MITRE cve.org data
                cveorg = cveorg_lookup.get_cve(cve_id)
                affected_data = cveorg.get("containers",{}).get("cna", {}).get("affected", [])

                cve_org_affected = set()

                for a in affected_data:
                    vendor, product = a.get("vendor", None), a.get("product", None)
                    cve_org_affected.add((vendor, product))

                if len(cve_org_affected) >= 1 and len(cpes) >= 1:
                    for affected in cve_org_affected:
                        # translated cpes
                        t_cpes = result_lookup.get(affected,set())
                        for c in cpes:
                            t_cpes.add(c)

                        result_lookup[affected] = t_cpes
                else:
                    no_info_list.append((cve_id, cve_org_affected, cpes))

    # ok now we have the list, but there can be amniguity when NVD and MTIRE disagree on matching
    # so let's do a first round of cleanups. If the vendor name of one of the options matches, but others don't, then remove
    # all where vendor names doesn't match. And same with product name

    for k in result_lookup.copy():
        v = result_lookup[k]
        if len(v) > 1:
            vendor, product = k
            new_val = set()
            # first try and remove operating systems/hardware, since thats often the source of duplicates
            for cpe in v:
                if cpe.split(":")[0] == "a":
                    new_val.add(cpe)

            if len(new_val) == 1:
                result_lookup[k] = new_val
                continue

            elif vendor is not None:
                new_val = set()

                # ok if that doesn't work see if only 1 has the correct vendor, then thats probably it
                vendor_str = vendor.lower().replace(" ", "_")
                product_str = product.lower().replace(" ", "_")

                for cpe in v:
                    if cpe.split(":")[1].lower().replace("\\", "") == vendor_str:
                        new_val.add(cpe)

                if len(new_val) == 1:
                    result_lookup[k] = new_val
                    continue
                else:
                    # ok maybe exactly one matches the product name?
                    new_val = set()


                    for cpe in v:
                        cpe_product = cpe.split(":")[2].lower().replace("\\", "")

                        if product_str.startswith(cpe_product):
                            new_val.add(cpe)

                    if len(new_val) == 1:
                        result_lookup[k] = new_val
                        continue
    return result_lookup


if __name__ == "__main__":
    from enhance_utils import CveOrgLookup
    result_lookup = build_cveorg_to_cpe_lookup(CveOrgLookup("./NVD_DATA/cvelistV5-main.zip"))
    num = 0
    for k,v in result_lookup.items():
        if len(v) > 1:
            num+=1
            print(f"{k}->{v}")
    print(num, len(result_lookup), num/len(result_lookup)*100)



