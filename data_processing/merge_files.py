import argparse
from pathlib import Path
from pprint import pprint
from typing import Final
import csv_helpers
import os
import sys

#Argument parser code is modified from Gemini
parser = argparse.ArgumentParser(description="Processes glue and authoritative A and AAAA records to identify stale glue records") 
    
# Add positional (required) arguments
parser.add_argument("Num_DNs", help="The number of domain names run through YoDNS, used to identify the correct output folder", type=str)
args = parser.parse_args()


sys.argv = ["process_glue.py", f'{args.Num_DNs}+']
from process_glue import update_ct, create_result_files, write_report_merge



#FINAL VARIABLES__________________________________________________________________________________________________

NUM_DNS: Final[str] = args.Num_DNs

#Finding relevant file paths to access json files for parsing
BASE_DIR: Final[Path] = Path(__file__).resolve().parent.parent / 'YoDNS_output'/ f'Output_{NUM_DNS}_DN' / 'results' / 'stale_glue'

#FUNCTIONS_______________________________________________________________________________________________________
def merge_dicts(dicts: list[dict]):

    total_stale = {}

    for d in dicts:
        for DN, IPset in d.items():
                if DN not in total_stale:
                    total_stale[DN] = IPset
                else:
                    total_stale[DN] = total_stale[DN] | IPset

    return total_stale



def load_dict_files():
    '''Loads csv files containing dictionaries back into dictionaries'''

    incon_files = list(Path.glob(BASE_DIR, "Inconsistent_IPs-*.csv"))
    freq_files = list(Path.glob(BASE_DIR, "Stale_IP_Freq-*.csv"))

    #pprint(incon_files)
    #pprint(freq_files)
    
    stale_A_dicts = []
    stale_AAAA_dicts = []
    freq_dicts = []

    total_stale = []
    total_freq = {}

    for file in incon_files:
        _, stale_A, stale_AAAA = csv_helpers.read_csv(file, "Incon")
        stale_A_dicts.append(stale_A)
        stale_AAAA_dicts.append(stale_AAAA)

        os.remove(file)


    for file in freq_files:
        freq_dict, _, _  = csv_helpers.read_csv(file, "Freq")
        freq_dicts.append(freq_dict)

        os.remove(file)
    

    total_stale.append(merge_dicts(stale_A_dicts))
    total_stale.append(merge_dicts(stale_AAAA_dicts))

    for d in freq_dicts:
         for IP, freq in d.items():
            update_ct(total_freq, IP, freq)
    
    return total_stale, total_freq


def load_report():
    '''Loads txt files containing dictionaries back into dictionaries'''

    rep_files = list(Path.glob(BASE_DIR, "Stale_Glue_Stats*.txt"))

    stats_A = []
    stats_AAAA = []

    per_A = []
    per_AAAA = []


    for file in rep_files:
        with open(file, 'r') as f:
            content = f.readlines()

            stats = []
            percents = []

            for line in content:
                line = line.strip().split(" ")

                totals = line[5].split("/")
                total_stale = int(totals[0])
                total_glue = int(totals[1])

                unique = line[7].split("/")
                unique_stale = int(unique[0])
                unique_glue = int(unique[1])

                ns = line[13].split("/")
                ns_stale = int(ns[0])
                ns_glue = int(ns[1])

                percents.append((round((float(unique_stale)/unique_glue)*100, 5), round((float(ns_stale)/ns_glue)*100, 5)))

                stats.append((total_stale, total_glue))

        stats_A.append(stats[0])
        stats_AAAA.append(stats[1])

        per_A.append(percents[0])
        per_AAAA.append(percents[1])
    
        os.remove(file)

    return [stats_A, stats_AAAA], [per_A, per_AAAA]

def ct_type(freq: dict):
    '''Counts the number of unique A and AAAA records are in the merged frequency dictionary'''

    A_ct = 0
    AAAA_ct = 0

    for IP in freq.keys():

        if "." in IP:
            A_ct += 1
        else:
            AAAA_ct +=1
    return (A_ct, AAAA_ct)



def calc_totals(stats: list[tuple]):
    '''Merges the totals of txt file reports to get statistics reflective of the entire DN number, not to each batch'''

    grand_total_stats = [0,0]

    for tup in stats:
        for i in range(len(tup)):

            grand_total_stats[i] += tup[i]

    percent = round((float(grand_total_stats[0])/grand_total_stats[1])*100, 5)

    return [grand_total_stats[0], grand_total_stats[1], percent]

def calc_avg(pers: list[tuple]):
    '''Averages the percents of txt file reports to get statistics reflective of the entire DN number, not to each batch'''

    avg_pers = [0,0]

    for tup in pers:
        for i in range(len(tup)):

            avg_pers[i] += tup[i]
        
    for i in range(len(avg_pers)):
        if avg_pers[i] != 0:
            avg_pers[i] = round(avg_pers[i]/len(pers), 5)
        else:
            avg_pers[i] = 0.0 # Avoid division by zero error

    return avg_pers


def main():

    stale_dicts, freq_dict = load_dict_files()

    totals = ct_type(freq_dict)

    stats_list, percent_list = load_report()
    #print(percent_list)

    stats = []
    
    #Total stats by record type (A and AAAA)
    for i in range(len(stats_list)):

        percent_list[i] = calc_avg(percent_list[i])

        stats.append(calc_totals(stats_list[i]) + [totals[i], percent_list[i][0], len(stale_dicts[i]), percent_list[i][1]])

    create_result_files(stale_dicts, freq_dict)
    write_report_merge(stats)

main()
