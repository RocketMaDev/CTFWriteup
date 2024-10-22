#include "ingredient.h"

static void garlic(void) {
    printf("加蒜蓉");
}

void AddGarlic(void) {
    static bool added = false;
    if (!added) {
        puts("Add some garlic.");
        added = true;
        regfunc(garlic);
    } else {
        puts("You have added garlic!");
    }
}

static void coriander(void) {
    printf("加香葱");
}

void AddCoriander(void) {
    static bool added = false;
    if (!added) {
        puts("Add some coriander.");
        added = true;
        regfunc(coriander);
    } else {
        puts("You have added coriander!");
    }
}
