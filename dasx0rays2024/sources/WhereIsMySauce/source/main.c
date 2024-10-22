#include "main.h"
#include "dish.h"
#include "ingredient.h"
#include "liquid.h"
#include <stdio.h>

#define MAX_ITEMS 10

const char *dishes[] = {"火腿鸡蛋", "麻辣烫", "缙云烧饼", "香肠炒饭", "咸菜豆腐",
                    "炒青菜", "大排面", "泡面", "番茄蛋花汤", "烤肉饭"};

static int sp = 0;
FUNCPTR todos[MAX_ITEMS];

void regfunc(FUNCPTR func) {
    todos[sp++] = func;   
}

int main(void) {
    const char *dish = SelectADish();
    PrintIngredient();
    int choice;
    do {
        scanf("%d", &choice);
        switch (choice) {
            case 1: AddGarlic(); break;
            case 2: AddCoriander(); break;
            case 3: AddOil(); break;
            case 4: AddWater(); break;
            case 5: AddSauce(true); break;
            default: AddSauce(false); break;
        }
    } while(choice > 0 && choice < 6);
    puts("");
    puts("The dish you will cook is:");
    printf(GREEN_TXT);
    for (int i = 0; i < sp; i++)
        todos[i]();
    printf("%s" DEFAULT_TXT "\n", dish);
    return 0;
}
