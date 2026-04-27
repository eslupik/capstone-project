import json
from pathlib import Path
from pprint import pprint
from typing import Final


num_dns = '5101'
NUM_DNs: Final[str] = num_dns

AUTH_MESSAGE: Final[str] = 'Answer'
GLUE_MESSAGE: Final[str] = 'GlueRecords' 
#Finding relevant file paths to access json files for parsing
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNs}_DN' / 'filtered'

AUTH_A_DIR: Final[Path] = BASE_DIR / 'Auth' / 'A_REC'
GLUE_A_DIR: Final[Path] = BASE_DIR / 'Glue' / 'A_Glue'

AUTH_AAAA_DIR: Final[Path] = BASE_DIR / 'Auth' / 'AAAA_REC'
GLUE_AAAA_DIR: Final[Path] = BASE_DIR / 'Glue' / 'AAAA_Glue'



def load_json_file(filepath: Path, message_type: str):
    '''Loads relevant data from all json files in a folder into an dictionary of a specified type 
    (authoritative or glue) for analysis'''

    json_files = list(Path.glob(filepath, "*.json"))
    #print(json_files)

    rec_dict = {}

    for file in json_files:
        # Open and load the JSON file
        with open(file, 'r') as f: 
        #(Gemini was used for this code to create this inner loop because I wasn't fully sure how to parse json objects)
            for line in f:
                # Each line is a complete, valid JSON object
                entry = json.loads(line)
                #pprint(entry)
                process_json(rec_dict, entry, message_type)

    #pprint(rec_dict)
    return rec_dict


def process_json(rec_dict: dict, entry: dict, message_type: str):
    '''Processes the contents of a json file containing records (glue or authoritative) and creates a 
    dictionary mapping domain names (keys, strings) to  records (values, a set of strings)'''

    answer = entry[message_type]

    for record in answer:
        DN = record['Name']

        if DN not in rec_dict:
            rec_dict[DN] = set()
        
        rec_dict[DN].add(record['Value'])
    #pprint(rec_dict)


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

    pprint(inconsistent_dict)
    return inconsistent_dict


def main():

    #For A (Ipv4) records:
    auth_A_dict = load_json_file(AUTH_A_DIR, AUTH_MESSAGE)
    glue_A_dict = load_json_file(GLUE_A_DIR, GLUE_MESSAGE)
    #Identify inconsistent glue A records (not present in authorized records)
    inconsistent_A_glue = compare_recs(auth_A_dict, glue_A_dict)

    #For AAAA (Ipv6) records:
    auth_AAAA_dict = load_json_file(AUTH_AAAA_DIR, AUTH_MESSAGE)
    glue_AAAA_dict = load_json_file(GLUE_AAAA_DIR, GLUE_MESSAGE)
    #Identify inconsistent glue AAAA records (not present in authorized records)
    inconsistent_AAAA_glue = compare_recs(auth_AAAA_dict, glue_AAAA_dict)

    






main()





    