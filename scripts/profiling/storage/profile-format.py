#!/usr/bin/python

import argparse
import pstats


def parse_args():
    # parse command line
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-f', dest='statsfiles', action='append', required=True,
        help='a stats file')
    args = parser.parse_args()
    return args.statsfiles


def format_stats(statsfiles):
    for f in statsfiles:
        ps = pstats.Stats(f)
        ps.strip_dirs()
        ps.sort_stats('time')
        ps.print_stats()
        ps.sort_stats('cumulative')
        ps.print_stats()


if __name__ == '__main__':
    statsfiles = parse_args()
    format_stats(statsfiles)
