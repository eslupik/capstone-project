import argparse
import json
from pathlib import Path
from pprint import pprint
from typing import Final
import dns.resolver
import csv_helpers
from io import TextIOWrapper
import zstandard as zstd
import os



#Argument parser code is modified from Gemini
parser = argparse.ArgumentParser(description="Processes glue and authoritative A and AAAA records to identify stale glue records") 
    
# Add positional (required) arguments
parser.add_argument("Num_DNs", help="The number of domain names run through YoDNS, used to identify the correct output folder", type=str)
args = parser.parse_args()

#FINAL VARIABLES__________________________________________________________________________________________________
arg_str = str(args.Num_DNs)
args = arg_str.split("+")

NUM_DNS: Final[str] = args[0]

if len(args) > 0:
    batch = args[1]
else:
    batch = ""

AUTH_MESSAGE: Final[str] = 'Answer'
GLUE_MESSAGE: Final[str] = 'GlueRecords' 

A_NAME: Final[str] = 'A'
A_TYPE: Final[int] = 1

AAAA_NAME: Final[str] = 'AAAA'
AAAA_TYPE: Final[int] = 28

#Finding relevant file paths to access json files for parsing
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNS}_DN' / f'filtered/{batch}'

AUTH_A_DIR: Final[Path] = BASE_DIR / 'Auth' / 'A_REC'
GLUE_A_DIR: Final[Path] = BASE_DIR / 'Glue' / 'A_Glue'

AUTH_AAAA_DIR: Final[Path] = BASE_DIR / 'Auth' / 'AAAA_REC'
GLUE_AAAA_DIR: Final[Path] = BASE_DIR / 'Glue' / 'AAAA_Glue'

REC_TYPES: Final[list] = [(A_NAME, A_TYPE, AUTH_A_DIR, GLUE_A_DIR), (AAAA_NAME, AAAA_TYPE, AUTH_AAAA_DIR, GLUE_AAAA_DIR)]


NAME: Final[int] = 0
TYPE: Final[int] = 1
AUTH_DIR: Final[int] = 2
GLUE_DIR: Final[int] = 3

NAMES: Final[list] = [rec[NAME] for rec in REC_TYPES]


OUTPUT: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNS}_DN' / 'results' / 'stale_glue'
INCON_HEADERS: Final[list[str]] = ['Domain Name', 'Inconsistent IPs', 'IP Record Type']
FREQ_HEADERS: Final[list[str]] = ['Stale IP', 'Frequency (encountered in YoDNS search)']


#FUNCTIONS_______________________________________________________________________________________________________
def load_json_file(filepath: Path, message_type: str):
    '''Loads relevant data from all json files in a folder into an dictionary of a specified type 
    (authoritative or glue) for analysis; Gemini was used to modify this existing function to utilize the python 
    zstandard library to read compressed .json.zst files to prevent the disk from filling up!'''

    # Update glob to look for .zst files
    json_files = list(Path.glob(filepath, "*.json.zst"))
    #pprint(json_files)
    
    rec_dict = {}
    glue_ct_dict = {}
    total_glue = 0
    
    dctx = zstd.ZstdDecompressor()

    for file in json_files:
        with open(file, 'rb') as fh:
            # stream_reader handles the decompression
            with dctx.stream_reader(fh) as reader:
                # TextIOWrapper lets us treat the binary stream as a text file
                with TextIOWrapper(reader, encoding='utf-8') as f:
                    for line in f:
                        if not line.strip():
                            continue
                        # In process_glue.py, around line 91:
                        try:
                            entry = json.loads(line)
                        except json.decoder.JSONDecodeError as e:
                            print(f"Error parsing JSON on this line: {line}")
                            print(f"Error details: {e}")
                            continue  # Skip this line
                        #pprint(entry)
                        total_glue += process_json(rec_dict, entry, glue_ct_dict, message_type)
                        
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


def update_ct(ct_dict: dict, IP: str, toAdd: int = 1):
    '''Increments the frequency count recording glue records for each IP (A or AAAA record)'''

    if IP in ct_dict:
        ct_dict[IP] += toAdd
    else:
        ct_dict[IP] = toAdd


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
    '''Prompts a stale glue candidate IP for its supposed name's A or AAAA record and verifies if it provides its own IP'''

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_ip]  # Direct the query to your old IP
    resolver.timeout = 2             # How long to wait for a response
    resolver.lifetime = 2

    try:
        answer = resolver.resolve(ns_hostname, rec_type) #Ask IP for its own IP (A or AAAA) record
        
        recs = [addr.to_text() for addr in answer]

        if dns_ip in recs:
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


def verify_stale(inc_dict: dict, glue_freq: dict, rec_type: str):
    '''Takes dicts of identified inconsistent glue records and performs NS lookups on these IPs to determine if they are stale'''

    stale_dict = {}
    stale_freq_d = {}
    total_stale = 0

    for DN, IPset in inc_dict.items():

        for IP in IPset:
            if is_stale(IP, DN, rec_type):

                update_ct(stale_freq_d, IP, glue_freq[IP])
                total_stale += glue_freq[IP]
                
                if DN not in stale_dict:
                    stale_dict[DN] = set()

                stale_dict[DN].add(IP)

    return stale_dict, stale_freq_d, total_stale


def calc_total_stale(stale_dict: dict, ct_dict: dict):
    '''Calculates the total number of encountered stale glue records of a specific type 
    using a dict mapping DNs to stale IPs and the frequency of those IPs in glue records'''

    total_stale = 0
    unique_stale = 0

    for DN, IPset in stale_dict.items():

        for IP in IPset:

            total_stale += ct_dict[IP]

    return total_stale, unique_stale



def check_exists(name, suffix):
    '''Generates appropriate file name so as to not overwrite existing files in the results folder'''
    filename = OUTPUT / f'{name}.{suffix}'
    counter = 1

    # Check if file exists and increment counter until a unique name is found, Gemini helped with the counter idea
    while os.path.exists(filename):
        filename = OUTPUT / f'{name}_{counter}.{suffix}'
        counter += 1


    return filename



def write_report(stats):
    '''Write final analytics report to a txt file'''

    filename = check_exists(f'Stale_Glue_Stats-{NUM_DNS}', 'txt')

    with open(filename, "w") as file: #Used Gemini to remind me of the syntax to write to a txt file
        
        for i in range(len(NAMES)):
            file.write(f"{i+1}. Total stale {NAMES[i]} recs: {stats[i][0]}/{stats[i][1]} ({stats[i][2]}%), {stats[i][3]}/{stats[i][4]} unique stale IP(s) ({stats[i][5]}%) from {stats[i][6]}/{stats[i][7]} unique NS names ({stats[i][8]}%).\n")



def write_report_merge(stats):
    '''Write final analytics report to a txt file AFTER A MERGE'''

    filename = check_exists(f'Stale_Glue_Stats-{NUM_DNS}', 'txt')

    with open(filename, "w") as file: #Used Gemini to remind me of the syntax to write to a txt file
        
        for i in range(len(NAMES)):
            file.write(f"{i+1}. Total stale {NAMES[i]} recs: {stats[i][0]}/{stats[i][1]} ({stats[i][2]}%), {stats[i][3]} unique stale IP(s) (Avg: {stats[i][4]}%) from {stats[i][5]} unique NS names (Avg: {stats[i][6]}%).\n")




def create_result_files(stale_dicts: list, stale_freq:dict):
    '''All exporting functionality to .txt or .csv files'''

    #Write identified inconsistent glue records to a csv file
    filename = check_exists(f'Inconsistent_IPs-{NUM_DNS}', 'csv')
    csv_helpers.write_csv(stale_dicts, NAMES, filename, INCON_HEADERS)

    #Write identified glue records and their frequency to a csv file
    filename = check_exists(f'Stale_IP_Freq-{NUM_DNS}', 'csv')
    csv_helpers.write_csv_dict(stale_freq, filename, FREQ_HEADERS)



def main():

    stale_dicts = []
    stats = []
    freq_dicts = []

    for rec_type in REC_TYPES:

        #Get dictionaries for all unique authoritative and glue records of a type
        auth_dict = load_json_file(rec_type[AUTH_DIR], AUTH_MESSAGE)[0]
        glue_dict, glue_ct_dict, total_glue = load_json_file(rec_type[GLUE_DIR], GLUE_MESSAGE)

        #Identify inconsistent glue records (not present in authorized records)
        inconsistent_glue = compare_recs(auth_dict, glue_dict)

        stale_glue, stale_freq, total_stale = verify_stale(inconsistent_glue, glue_ct_dict, rec_type[NAME])
        stale_dicts.append(stale_glue)
        freq_dicts.append(stale_freq)

        # pprint(inconsistent_glue)
        # pprint(glue_ct_dict)
        # print(total_glue)

        unique_stale = len(stale_freq)
        unique_total = len(glue_ct_dict)

        percent_stale = round((float(total_stale)/total_glue) *100, 5)
        percent_unique = round((float(unique_stale)/unique_total) *100, 5)
        percent_NS = round((float(len(stale_glue))/len(glue_dict)) *100, 5)
        
        stats.append((total_stale, total_glue, percent_stale, unique_stale, unique_total, percent_unique, len(stale_glue), len(glue_dict), percent_NS))
        print(f"Total stale {rec_type[NAME]} recs: {total_stale}/{total_glue} ({percent_stale}%), {unique_stale}/{unique_total} unique stale IP(s) ({percent_unique}%) from {len(stale_glue)}/{len(glue_dict)} unique NS names ({percent_NS}%).")
    

    stale_freq = {}
    for d in freq_dicts:
        # Combine frequency dictionaries
        stale_freq = stale_freq | d

    create_result_files(stale_dicts, stale_freq)

    #Write .txt report of statistics
    write_report(stats)

    
if __name__ == "__main__":
    main()






    