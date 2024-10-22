#include "dish.h"

const char *SelectADish(void) {
    puts("System automatically select a dish for you:");
    srand(time(NULL));
    const char *dish = dishes[rand() % DISH_CNT];
    printf(GREEN_TXT "%s" DEFAULT_TXT "\n", dish);
    return dish;
}

void PrintIngredient(void) {
    puts("What ingredients do you want to add?");
    puts("1. garlic");
    puts("2. coriander");
    puts("3. oil");
    puts("4. water");
    puts("5. sauce(Add it please!)");
    puts("6. done!");
}
