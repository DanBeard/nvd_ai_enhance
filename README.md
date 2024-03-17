# NVD AI Enhancement (Proof of Concept)

This is a proof of concept to see how useful an LLM can be in enhancing an CVE in a similar fashion to NIST.  Starting with generating cpe and matching information.


## TODOs in order to be broadly useful
- [ ] Generate comparisons with already establed CVE data 
- [ ] Enable more complicated match generation than just a single "OR" range
- [ ] Methodology for creating a CPE is one doesn't already exist
- [ ] Methodology for a human to confirm and increase confidence in a match (webui?)
- [ ] Methodology for a human to contradict and remove confidence in a match (webui?)
- [ ] Backend agnostic arch (Currently tied to Anthropic/Claude 3)



## Requirements
- Anthropic API key
- python 
- langchain

## Subjective Takeaways 