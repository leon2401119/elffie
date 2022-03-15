import sys
import os

def get_raw_bytes(filename):
    with open(filename,'rb') as f:
        raw_bytes = f.read()

    return raw_bytes


def main():
    if len(sys.argv) != 2:
        print('Supply one and only one executable to inspect')
        sys.exit()

    raw_bytes = get_raw_bytes(sys.argv[1])


if __name__ == '__main__':
    main()
