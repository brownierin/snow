import json
import csv
import argparse
import collections

def open_json(filename):
    with open(filename, "r") as file:
        data = json.load(file)
        file.close()
    return data


def convert_json_to_csv(fp_filename, csv_filename):
    fp_json = open_json(fp_filename)
    value = next(iter(fp_json))
    column_headers = collections.deque(fp_json[value].keys())
    column_headers.appendleft("hash_id")

    with open(csv_filename, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=',',
                                quotechar='"', quoting=csv.QUOTE_MINIMAL)
        csvwriter.writerow(column_headers)
        for fp in fp_json:
            value_list = collections.deque([value for key, value in fp_json[fp].items()])
            value_list.appendleft(fp)
            csvwriter.writerow(value_list)
        csvfile.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Converts a JSON file in format \"key: {values}\" to CSV"
    )
    parser.add_argument(
        "-fp",
        "--fp_filename",
        help="the dict of false positives for a given repository",
    )
    parser.add_argument(
        "-csv",
        "--csv_filename",
        help="the csv file of false positives",
    )
    args = parser.parse_args()
    convert_json_to_csv(args.fp_filename, args.csv_filename)
