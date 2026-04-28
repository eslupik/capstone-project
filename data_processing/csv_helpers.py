import csv
import ast
#Portions of this code are reused/modified from Emma's measure-main project

# 1. Read in .csv file
def read_csv(filename, csv_type):
    #Dictionary for storing DNs with ID numbers for debugging and 
    csv_dict = {}
    
    with open(filename, newline = '') as csvfile:
        to_read = csv.reader(csvfile, delimiter=',')

        header = next(to_read)

        for row in to_read:
            match csv_type:
                case 'Top DN':
                    csv_dict[row[0]] = row[1]

                case 'Records':
                    # csv_set = ()
                    # print(row[1])
                    # csv_set.update(row[1::])
                    csv_dict[row[0]] = set(ast.literal_eval(row[1]))
            
    return csv_dict

# print(read_csv('ASN_Records_DN-50.csv', 'Records'))


# 3. Create new .csv file and export
def write_csv_dict(dict, filename, fieldnames):

    with open(filename, 'w', newline='') as csvfile: #Syntax for writing to a csv file found from: https://docs.python.org/3/library/csv.html#csv.QUOTE_NONNUMERIC
        to_write = csv.DictWriter(csvfile, delimiter=",", quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames)

        to_write.writeheader()

        for ID, val in dict.items():
            to_write.writerow({fieldnames[0]: ID, fieldnames[1]: val})


def write_csv(A_dict, AAAA_dict, filename, fieldnames):

    with open(filename, 'w', newline='') as csvfile: #Syntax for writing to a csv file found from: https://docs.python.org/3/library/csv.html#csv.QUOTE_NONNUMERIC
        to_write = csv.writer(csvfile, delimiter=",", quoting=csv.QUOTE_MINIMAL)

        to_write.writerow(fieldnames)

        for DN, Ips in A_dict.items():
            to_write.writerow([DN, Ips, 'A'])

        for DN, Ips in AAAA_dict.items():
            to_write.writerow([DN, Ips, 'AAAA'])


