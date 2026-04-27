import json
from pathlib import Path
from pprint import pprint
from typing import Final


num_dns = '10'
NUM_DNs: Final[str] = num_dns

AUTH: Final[int] = 1
GLUE: Final[int] = 2 
#Finding relevant file paths to access json files for parsing
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNs}_DN' / 'filtered'

AUTH_A_DIR: Final[Path] = BASE_DIR / 'Auth' / 'A_REC'
GLUE_A_DIR: Final[Path] = BASE_DIR / 'Glue' / 'A_Glue'

AUTH_AAAA_DIR: Final[Path] = BASE_DIR / 'Auth' / 'AAAA_REC'
GLUE_AAAA_DIR: Final[Path] = BASE_DIR / 'Glue' / 'AAAA_Glue'



def load_json_file(filepath: Path):
    '''Loads data from all json files in a folder into an array for processing
    (warning, need to put every line of the yodns output files as an array entry or it cannot be loaded)'''

    json_files = list(Path.glob(filepath, "*.json"))
    #print(json_files)

    data = []

    for file in json_files:
        # Open and load the JSON file (these two lines were taken from Gemini)
        with open(file) as f:

            data.append(json.load(f))
            #pprint(data)

    return data


def process_json(auth_data: list, type: int):
    '''Processes the contents of a json file containing records (glue or authoritative) and creates a 
    dictionary mapping domain names (keys, strings) to  records (values, a set of strings)'''

    message = ''
    if type == AUTH:
        message = 'Answer'
    else:
        message = 'GlueRecords'

    
    rec_dict = {}

    for line in auth_data:

        for entry in line:
            answer = entry[message]

            for record in answer:
                DN = record['Name']

                if DN not in rec_dict:
                    rec_dict[DN] = set()
                
                rec_dict[DN].add(record['Value'])

    #pprint(rec_dict)
    return rec_dict


def compare_recs(auth_dict: dict, glue_dict: dict):

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
    auth_A_data = load_json_file(AUTH_A_DIR)
    auth_A_dict = process_json(auth_A_data, AUTH)

    glue_A_data = load_json_file(GLUE_A_DIR)
    glue_A_dict = process_json(glue_A_data, GLUE)

    inconsistent_A_glue = compare_recs(auth_A_dict, glue_A_dict)

    #For AAAA (Ipv6) records:
    auth_AAAA_data = load_json_file(AUTH_AAAA_DIR)
    auth_AAAA_dict = process_json(auth_AAAA_data, AUTH)

    glue_AAAA_data = load_json_file(GLUE_AAAA_DIR)
    glue_AAAA_dict = process_json(glue_AAAA_data, GLUE)

    inconsistent_AAAA_glue = compare_recs(auth_AAAA_dict, glue_AAAA_dict)

    






main()





    