#include "liquid.h"

static void too_much_water(void) {
    printf("纯汤");
}

void AddWater(void) {
    static bool added = false;
    if (!added) {
        puts("Add some water.");
        added = true;
    } else {
        puts("You have added water! Water will overflow!");
        regfunc(too_much_water);
    }
}

static void too_much_oil(void) {
    printf("超腻");
}

void AddOil(void) {
    static bool added = false;
    if (!added) {
        puts("Add some oil.");
        added = true;
    } else {
        puts("You have added oil! Oil will overflow!");
        regfunc(too_much_oil);
    }
}

static void too_much_sauce(void) {
    printf("齁咸");
}

static void rage(void) {
    puts(DEFAULT_TXT);
    puts("WHY!! THERE!! IS!! NO!! SAUCE!!");

    // We are sorry that your program is destroyed for the missing sauce
    // To make up for that we provided with you the flag: FLAG
    *(char *)NULL = 6;
}

void AddSauce(bool will) {
    static bool added = false;
    if (will)
        if (!added) {
            puts("Add some sauce.");
            added = true;
        } else {
            puts("You have added sauce! Sauce will be too much!");
            regfunc(too_much_sauce);
        }
    else if (!added)
            regfunc(rage);
}
