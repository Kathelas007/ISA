#!/usr/bin/env python3

import sys


def analyze():
    root_domains = dict()
    com_domains = dict()

    min_len = 1000
    max_len = 0
    with open(sys.argv[1], 'r') as f:
        for line in f.readlines():
            line.strip()
            last = line.split('.')[-1]

            try:
                root_domains[last] += 1
            except Exception as e:
                root_domains[last] = 0

            if last == 'com' and len(line.split('.')) >= 2:
                sec_last = line.split('.')[-2]
                try:
                    com_domains[sec_last] += 1
                except Exception as e:
                    com_domains[sec_last] = 0
    #
    # root_domains = {k: v for k, v in sorted(root_domains.items(), key=lambda item: item[1])}
    # for a, b in root_domains.items():
    #     print(a, b)

    com_domains = {k: v for k, v in sorted(com_domains.items(), key=lambda item: item[1])}
    for a, b in com_domains.items():
        print(a, b)

    print("min:", min_len, "max:", max_len)


def find():
    with open(sys.argv[1], 'r') as f:
        for line in f.readlines():
            line = line.strip()
            if line == sys.argv[2]:
                print("found")
                return
    print("not found")


if __name__ == "__main__":
    # analyze()
    find()
