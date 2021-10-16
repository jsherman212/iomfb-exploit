#!/usr/local/bin/python3

import statistics

iphone8_kernel_map_samples = [
        [0xffffffe8cee1c000, 0xffffffe8ec458000],
        [0xffffffe8cef78000, 0xffffffe8ec5b0000],
        [0xffffffe8ce9b4000, 0xffffffe8ebff4000],
        [0xffffffe8cef38000, 0xffffffe8ec570000],
        [0xffffffe8cead4000, 0xffffffe8ec10c000],
        [0xffffffe8ccdec000, 0xffffffe8ec378000],
]

iphonese_kernel_map_samples = [
        [0xfffffff9937e4000, 0xfffffff9aeedc000],
        [0xfffffff98352c000, 0xfffffff99ec24000],
        [0xfffffff981604000, 0xfffffff99ccfc000],
        [0xfffffff981a4c000, 0xfffffff99d144000],
]

def average_allocs(alloc_list):
    ptr_mask = 0xffffffffffffc000
    avgs = list()

    for alloc_range in alloc_list:
        nallocs = 0
        total = 0
        npages = 0

        curpage = alloc_range[0]
        last = alloc_range[1]

        while curpage < last:
            total += curpage
            npages += 1
            curpage += 0x4000

        avg = (total // npages) & ptr_mask
        avgs.append(avg)

    # Page align down
    guess = int(statistics.mean(avgs)) & ptr_mask

    satisfied = 0
    not_satisfied = 0

    for alloc_range in alloc_list:
        first = alloc_range[0]
        last = alloc_range[1]

        if guess >= first and guess < last:
            satisfied += 1
        else:
            not_satisfied += 1

    right_chance = (satisfied / len(alloc_list)) * 100.0

    print("Guess 0x%x (%.02f%% chance (%d/%d) of being right)" % \
            (guess, right_chance, satisfied, len(alloc_list)))

    return

def main():
    average_allocs(iphone8_kernel_map_samples)
    average_allocs(iphonese_kernel_map_samples)
    return

main()
