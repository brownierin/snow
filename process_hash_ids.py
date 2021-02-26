import json
import argparse

def open_json(filename):
    with open(filename, 'r') as file:
        data = json.load(file)
        file.close()
    return data

def write_json(filename, json_output):
    with open(filename, "w") as file:
        data = json.dumps(json_output)
        file.write(data)
        file.close()

def open_false_positives(filename):
    with open(filename) as file:
        read_in = file.readlines()
        file.close()
    false_positives = {}
    for line in read_in:
        try: 
            false_positives[line[:3]] = false_positives[line[:3]].append(line)
        except:
            false_positives[line[:3]] = [line]
    return false_positives

def remove_false_positives(json_filename, fp_filename, parsed_filename):
    data = open_json(json_filename)
    fp = open_false_positives(fp_filename)
    for issue in data['results']:
        hash_id = issue['hash_id']
        if fp[hash_id[:3]]:
            for fp_hash_id in fp[hash_id[:3]]:
                if fp_hash_id == hash_id:
                    data['results'].remove(issue)
    write_json(parsed_filename, data)
    # print(json.dumps(data, indent=4))
    return data

def get_hash_ids(data):
    hash_ids = {}
    # something's wrong in here, hashes aren't printing as expected
    for issue in data['results']:
        hash_id = issue['hash_id']
        try:
            hash_ids[hash_id[:3]] = hash_ids[hash_id[:3]].append(hash_id)
        except:
            hash_ids[hash_id[:3]] = [hash_id]
    return hash_ids

def compare_to_last_run(old_output, new_output, output_filename):
    old = open_json(old_output)
    new = open_json(new_output)
    old_hashes = get_hash_ids(old)
    new_hashes = get_hash_ids(new)
    print(f"old hashes: \n {old_hashes}")
    print(f"new hashes: \n {new_hashes}")
    if old_hashes == new_hashes:
        new['results'].clear()
        new['results'] = 'No new findings'
        write_json(output_filename, new)
        return results

    for new_issue_hash in new_hashes:
        try:
            bucket = old_hashes[new_issue_hash[0:3]]
            for old_hash in bucket:
                if old_hash == new_issue_hash:
                    [new['results'].remove(issue) for issue in new['results'] if issue['hash_id']==new_issue_hash]
                    print(f"removing issue {new_issue_hash}")
                    # for issue in new['results']:
                    #     if issue['hash_id'] == new_issue_hash:
                            
        except:
            continue
    write_json(output_filename, new)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Removes false positives from the final semgrep report.')
    parser.add_argument('-fp',
        '--fp_filename', 
        required=True,
        help='the list of false positives for a given repository')
    parser.add_argument('-i',
        '--json_filename', 
        required=True,
        help='the semgrep json data after hashes are assigned')
    parser.add_argument('-o',
        '--parsed_filename', 
        required=True,
        help='the resulting output filename')
    parser.add_argument('-od',
        '--output_diff',
        help='the file diff results are saved in')
    parser.add_argument('-in',
        '--input_new',
        help="the file for the latest scan")
    parser.add_argument('-io',
        '--input_old',
        help="the file for the previous scan to compare to")
    parser.add_argument('-c',
        '--compare',
        action='store_true',
        help="compare a previous run to a new run")
    args = parser.parse_args()
    remove_false_positives(args.json_filename, args.fp_filename, args.parsed_filename)
    if args.compare:
        compare_to_last_run(args.input_new, args.input_old, args.output_diff)