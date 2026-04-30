import argparse
import json
from pathlib import Path
from pprint import pprint
from typing import Final
import dns.resolver
import csv_helpers


#Argument parser code is modified from Gemini
parser = argparse.ArgumentParser(description="Processes glue and authoritative A and AAAA records to identify stale glue records") 
    
# Add positional (required) arguments
parser.add_argument("Num_DNs", help="The number of domain names run through YoDNS, used to identify the correct output folder", type=int)
args = parser.parse_args()

#FINAL VARIABLES__________________________________________________________________________________________________
NUM_DNS: Final[str] = str(args.Num_DNs)

AUTH_MESSAGE: Final[str] = 'Answer'
GLUE_MESSAGE: Final[str] = 'GlueRecords' 

A_NAME: Final[str] = 'A'
A_TYPE: Final[int] = 1

AAAA_NAME: Final[str] = 'AAAA'
AAAA_TYPE: Final[int] = 28

#Finding relevant file paths to access json files for parsing
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNS}_DN' / 'filtered'

AUTH_A_DIR: Final[Path] = BASE_DIR / 'Auth' / 'A_REC'
GLUE_A_DIR: Final[Path] = BASE_DIR / 'Glue' / 'A_Glue'

AUTH_AAAA_DIR: Final[Path] = BASE_DIR / 'Auth' / 'AAAA_REC'
GLUE_AAAA_DIR: Final[Path] = BASE_DIR / 'Glue' / 'AAAA_Glue'

REC_TYPES: Final[list] = [(A_NAME, A_TYPE, AUTH_A_DIR, GLUE_A_DIR), (AAAA_NAME, AAAA_TYPE, AUTH_AAAA_DIR, GLUE_AAAA_DIR)]

NAME: Final[int] = 0
TYPE: Final[int] = 1
AUTH_DIR: Final[int] = 2
GLUE_DIR: Final[int] = 3



OUTPUT_CSV: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNS}_DN' / 'results' / 'stale_glue' / f'Inconsistenst_IPs-{NUM_DNS}.csv'
INCON_HEADERS: Final[list[str]] = ['Domain Name', 'Inconsistent IPs', 'IP Record Type']

OUTPUT_TXT: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNS}_DN' / 'results' / 'stale_glue' / f'Stale_Glue_Stats-{NUM_DNS}.txt'


#FUNCTIONS_______________________________________________________________________________________________________
def load_json_file(filepath: Path, message_type: str):
    '''Loads relevant data from all json files in a folder into an dictionary of a specified type 
    (authoritative or glue) for analysis'''

    json_files = list(Path.glob(filepath, "*.json"))
    #pprint(json_files)

    rec_dict = {}
    glue_ct_dict = {}
    total_glue = 0

    for file in json_files:
        # Open and load the JSON file
        with open(file, 'r') as f: 
        #(Gemini was used for this code to create this inner loop because I wasn't fully sure how to parse json objects)
            for line in f:
                # Each line is a complete, valid JSON object
                entry = json.loads(line)
                #pprint(entry)
                total_glue += process_json(rec_dict, entry, glue_ct_dict, message_type)

    #pprint(rec_dict)
    return rec_dict, glue_ct_dict, total_glue


def process_json(rec_dict: dict, entry: dict, glue_ct_dict: dict, message_type: str):
    '''Processes the contents of a json file containing records (glue or authoritative) and creates a 
    dictionary mapping domain names (keys, strings) to  records (values, a set of strings)'''
    
    glue_ct = 0
    answer = entry[message_type]

    for record in answer:
        #Filter out answer signatures/other record types within the answer resource records
        if record['Type'] in [rec_type[TYPE] for rec_type in REC_TYPES]: 

            DN = record['Name']
            IP = record['Value']

            glue_ct += 1

            if DN not in rec_dict:
                rec_dict[DN] = set()
            
            rec_dict[DN].add(IP)

            if message_type == GLUE_MESSAGE:
                #Keep track of the number of glue records found for each IP to estimate proportions of stalee glue records encountered by YoDNS
                update_ct(glue_ct_dict, IP)
    #pprint(rec_dict)
    return glue_ct


def update_ct(ct_dict: dict, IP: str):
    '''Increments the frequency count recording glue records for each IP (A or AAAA record)'''

    if IP in ct_dict:
        ct_dict[IP] += 1
    else:
        ct_dict[IP] = 1


def compare_recs(auth_dict: dict, glue_dict: dict):
    '''Compares the records of two dictionaries to determine if there are glue records not validated by authoritative records'''

    #Create dict to store entries present in glue records but not authoritative records
    inconsistent_dict = {} 

    auth_keys = auth_dict.keys()
    glue_keys = glue_dict.keys()

    shared_keys = auth_keys & glue_keys #Find DNs with recorded authoritative and glue records

    for DN in shared_keys:

        inconsistent_dict[DN] = glue_dict[DN]-auth_dict[DN]
        if not inconsistent_dict[DN]:
            inconsistent_dict.pop(DN)

    #pprint(inconsistent_dict)
    return inconsistent_dict


#This function (with modifications) was created by Gemini
def is_stale(dns_ip: str, ns_hostname: str, rec_type: str):
    '''Prompts a stale glue candidate IP for its supposed name's A record and verifies if it provides its own IP'''

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_ip]  # Direct the query to your old IP
    resolver.timeout = 2             # How long to wait for a response
    resolver.lifetime = 2

    try:
        answer = resolver.resolve(ns_hostname, rec_type) #Ask IP for its own A record
        
        A_recs = [addr.to_text() for addr in answer]

        if dns_ip in A_recs:
            #print(f"Glue still works! A_recs found: {A_recs}\n Reverse lookup response: for {ns_hostname}: {ns_names}.")
            return False
        else:
            #print("Nah, glue is stale")
            return True
    except (dns.resolver.NoNameservers, dns.resolver.Timeout):
        #print(f"Failed: {dns_ip} is unresponsive.")
        return True
    except Exception as e:
        #print(f"Error checking {dns_ip}: {e}")
        return True


def verify_stale(inc_dict: dict, rec_type: str):
    '''Takes dicts of identified inconsistent glue records and performs NS lookups on these IPs to determine if they are stale'''

    for DN, IPset in inc_dict.items():

        for IP in IPset:
            if not is_stale(IP, DN, rec_type):
                inc_dict[DN].remove(IP)
                print("IP removed!")

        if not inc_dict[DN]:
            inc_dict.pop(DN)



def calc_total_stale(stale_dict: dict, ct_dict: dict):
    '''Calculates the total number of encountered stale glue records of a specific type 
    using a dict mapping DNs to stale IPs and the frequency of those IPs in glue records'''

    total_stale = 0
    unique_stale = 0

    for DN, IPset in stale_dict.items():

        for IP in IPset:

            unique_stale += 1
            total_stale += ct_dict[IP]

    return total_stale, unique_stale



def write_report(stats, lens, names):
    '''Write final analytics report to a txt file'''

    with open(OUTPUT_TXT, "w") as file: #Used Gemini to remind me of the syntax to write to a txt file
        
        for i in range(len(lens)):
            file.write(f"{i+1}. Total stale {names[i]} recs: {stats[i][0]}/{stats[i][1]} ({stats[i][2]}%),\n {stats[i][3]} unique stale IP(s) from {lens[i]} NS names.\n")


def main():

    inconsistent_dicts = []
    stats = []

    for rec_type in REC_TYPES:

        #Get dictionaries for all unique authoritative and glue records of a type
        auth_dict = load_json_file(rec_type[AUTH_DIR], AUTH_MESSAGE)[0]
        glue_dict, glue_ct_dict, total_glue = load_json_file(rec_type[GLUE_DIR], GLUE_MESSAGE)

        #Identify inconsistent glue records (not present in authorized records)
        inconsistent_glue = compare_recs(auth_dict, glue_dict)

        verify_stale(inconsistent_glue, rec_type[NAME])
        inconsistent_dicts.append(inconsistent_glue)

        # pprint(inconsistent_glue)
        # pprint(glue_ct_dict)
        # print(total_glue)

        total_stale, unique_stale = calc_total_stale(inconsistent_glue, glue_ct_dict)
        percent_stale = round((float(total_stale)/total_glue)*100, 5)

        stats.append((total_stale, total_glue, percent_stale, unique_stale))
        print(f"Total stale {rec_type[NAME]} recs: {total_stale}/{total_glue} ({percent_stale}%), {unique_stale} unique stale IP(s) from {len(inconsistent_glue)} NS names.")
    
    names = [rec[NAME] for rec in REC_TYPES]

    #Write identified inconsistent glue records to a csv file
    csv_helpers.write_csv(inconsistent_dicts, names, OUTPUT_CSV, INCON_HEADERS)
    write_report(stats, [len(d) for d in inconsistent_dicts], names)
    

    






main()





    