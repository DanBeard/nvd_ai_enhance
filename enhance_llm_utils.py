import json
import time
import textdistance
import csv
import traceback

from langchain_community.document_loaders import WebBaseLoader
import requests
# from bs4 import BeautifulSoup
from comparison_parser import turn_alg_into_nodes
from langchain_anthropic import ChatAnthropic
from langchain_core.prompts import ChatPromptTemplate
from langchain.globals import set_llm_cache
from langchain.cache import SQLiteCache
from langchain_community.document_loaders import PyPDFLoader
import langchain

langchain.verbose = True

set_llm_cache(SQLiteCache(database_path=".langchain.db"))

CPE_INFO_PROMPT = """Translate CVE descriptions into short algebraic expressions contained in JSON form. Given the description provided, generate a mathematical statement that will determine if a product is vulnerable based on it's version.
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
<example>""".replace('{', '{{').replace('}', '}}')

CPE_LOOKUP_PROMPT = """
You are a helpful AI bot programmed to lookup CPEs from product names
Given the supplied product name return the CPE 2.3 string that represents that product. Return only the CPE string and no explanation
valid cpe 2.3 strings always begin with cpe:2.3:
If there is not enough information to generate a result return an empty string

"""


class LLM_Utils():

    def __init__(self) -> None:
        # self.chat = ChatAnthropic(temperature=0, model_name="claude-3-sonnet-20240229")
        self.chat = ChatAnthropic(temperature=0, model_name="claude-3-haiku-20240307")

    def get_cpe_info(self, summary):
        system = (CPE_INFO_PROMPT)
        human = "<description>\n{summary}\n</description>\n result:{{"  # \n<reference_info>{ref_info}</reference_info>"
        prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])

        chain = prompt | self.chat
        result = chain.invoke(
            {
                "summary": summary,
                # "ref_info": ref_info
            }
        )

        # sometimes we don't get the "{" because we prepended it up top tp encourage a valid JSOn output from the LLM
        content = result.content
        if not content.strip().startswith("{"):
            content = "{" + content.strip()
        try:
            return json.loads(content)
        except json.decoder.JSONDecodeError as e:
            print("Decode error:" + content)
        return None

    def lookup_cpes(self, vendor_name, product_name, license_name=None, potential_cpes=None):
        system = CPE_LOOKUP_PROMPT + ((
                  "here is an incomplete list of potential cpes that might match." +
                  " Take an informed guess using the examples as a starting point " +
                  " The cpe may or may not be in this list.\n<example_cpes>\n" + "\n".join(potential_cpes) + "</example_cpes>\n\n"
                  ) if potential_cpes is not None else "")

        human = (f"<vendor>{vendor_name}</vendor>\n" if vendor_name is not None else "") \
                + "<product>{product_name}</product>" \
                + (f"\n<license>{license_name}</license>" if license_name is not None else "")
        # Pimcore's Admin Classic Bundle
        prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])
        chain = prompt | self.chat
        result = chain.invoke(
            {
                "product_name": product_name
            }
        )

        return result.content.split("\n")

    def does_ai_think_this_matches(self, product_name, nearest_cpe):
        system = (
            "You are a helpful AI bot that checks if CPEs are valid. does the provided CPE match the provided product name? answer with a simple yes or no:"
        )
        human = "<cpe>{cpe}</cpe>\n<product_name>{product_name}</product_name>"
        prompt = ChatPromptTemplate.from_messages([("system", system), ("human", human)])

        chain = prompt | self.chat
        result = chain.invoke(
            {
                "cpe": nearest_cpe,
                "product_name": product_name
            }
        )

        print(F"asking AI does {nearest_cpe} == {product_name}")
        print(result.content)
        return result.content.strip().lower() == "yes"
