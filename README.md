# NVD AI Enhancement (Proof of Concept)

This is a proof of concept to see how useful an LLM can be in enhancing an CVE in a similar fashion to NIST.  Starting with generating cpe and matching information.

Current technique is to use simple instruction prompts with Anthropics Claude Haiku model to create CPE matching info based purely on a CVE description.

## TODOs

### in order to be broadly useful
- [ ] Methodology for creating a CPE if one doesn't already exist
- [ ] Methodology for a human to confirm and increase confidence in a match (webui?)
- [ ] Methodology for a human to contradict and remove confidence in a match (webui?)
- [ ] Backend agnostic arch (Currently tied to Anthropic/Claude 3)

### further enhancements
- [x] Generate comparisons with already establed CVE data 
- [x] Enable more complicated match generation than just a single "OR" version range
- [ ] When matching CPE already in NIST dictionary, provide more choices to LLM based on different methodologies (Just vendor or just product matches for instance)
- [ ] Add external reference data to a pre-prompt to enhance CPE match accuracy
- [ ] Use embeddeding vectors instead of JAroWInkler for "close" cpe lookup logic

## Requirements
- Anthropic API key
- python > 3.10
- `pip install -r requirements.txt`

## Example Enhancement Data
Check out /example_data/ for an auto-enhanced version of recent CVE data. Accuracy is unknown. 


## Stat Data

Was only tested on 980 CVEs from 2023 with known enhancements.  Full metadata output for each CVE is in the test_data folder. Stats can be cndensed down with `compare_stats.py`
Takeaway is a roughly 79% success rate with cpe enhancement (~90% if partial matches count as success). or :
```
Num correct:768
Num partial:109
Num empty:0
Num vendor_only wrong:18
Num wrong:80
Num errors:0
total:975
```

## Subjective Takeaways
Below are some subjective takeaways that aren't based on any rigourous scientific methodologies but are hopefully interesting anyway:

 
-  Cpe generation from a CVE details paragraph seems to be surprisingly good. Claude will generate a valid CPE string that may or may not be valid. When it's not exactly valid, and there exists a valid CPE in the CPE dictionary provided by NIST, then a simple closest-string-by-JaroWinkler search strategy will find it. A simple re-check with a prompt like "Does this cpe make sense for the product instead?" seems to very accurately discern valid matches vs matched that are textually close but not valid. For Example : asking it if `cpe:2.3:a:jwt_project:jwt:-:*:*:*:*:*:*:*` is valid for the product `JWX` it correctly returns "No" despite being very close text distance. If asked about `cpe:2.3:a:lestrrat-go:jwx:*:*:*:*:*:*:*:*` and provided with the CVE description in the chat context (which mentions golang), it correctly returns "Yes" despite being much further text-distance

- When matching criteria has more info than just a simple "versions between x and y", it tries to encode that info into a boolean expression with variable named (e.g. `authenticated_read_write_administrator && (javascript_payload_stored_in_web_interface && javascript_payload_executed_in_another_administrator_browser)`) . Right now we just strip that out, but could this somehow be leveraged to add something like CWEs? 

- This was done by one amateur in less than 30 hours of development. It consumed less than $4 of Anthropic credits on the lowest API level. Rate limits were hit often during development. With more time, expertise, prompt engieering and high token limits there are absolutey room for VAST improvements 

