// hos_challenge.c - House of Spirit CTF Challenge
// Build: gcc -no-pie -fno-stack-protector -O2 -o hos_challenge hos_challenge.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#define MAX_ITEMS 8

typedef struct {
    size_t size;
    char *data;
} Item;

Item *items[MAX_ITEMS];
int item_count = 0;

void banner() {
    puts("=====================================");
    puts("     Memory Manager v1.0");
    puts("     Challenge: Get the flag!");
    puts("=====================================");
    puts("");
}

void print_flag() {
    FILE *f = fopen("flag.txt", "r");
    if (f) {
        char flag[100];
        fgets(flag, sizeof(flag), f);
        printf("Congratulations! Here's your flag:\n%s\n", flag);
        fclose(f);
    }
    exit(0);
}

void add_item() {
    if (item_count >= MAX_ITEMS) {
        puts("[-] Memory manager full!");
        return;
    }
    printf("Size: ");
    size_t size;
    if (scanf("%zu", &size) != 1) return;
    getchar();
    if (size == 0 || size > 0x1000) {
        puts("[-] Invalid size!");
        return;
    }
    Item *item = malloc(sizeof(Item));
    item->data = malloc(size);
    item->size = size;
    items[item_count] = item;
    printf("Data: ");
    fgets(item->data, size, stdin);
    printf("[+] Item %d created (size: 0x%zx)\n", item_count, size);
    item_count++;
}

void view_item() {
    printf("Index: ");
    int idx;
    if (scanf("%d", &idx) != 1) return;
    getchar();
    if (idx < 0 || idx >= item_count || !items[idx]) {
        puts("[-] Invalid index!");
        return;
    }
    printf("Item %d (size: 0x%zx): %s", idx, items[idx]->size, items[idx]->data);
}

void edit_item() {
    printf("Index: ");
    int idx;
    if (scanf("%d", &idx) != 1) return;
    getchar();
    if (idx < 0 || idx >= item_count || !items[idx]) {
        puts("[-] Invalid index!");
        return;
    }
    printf("New data: ");
    fgets(items[idx]->data, items[idx]->size, stdin);
    puts("[+] Item updated");
}

void delete_item() {
    printf("Index: ");
    int idx;
    if (scanf("%d", &idx) != 1) return;
    getchar();
    if (idx < 0 || idx >= item_count || !items[idx]) {
        puts("[-] Invalid index!");
        return;
    }
    free(items[idx]->data);
    free(items[idx]);
    items[idx] = NULL;
    puts("[+] Item deleted");
}

// debug_info receives both the fake chunk addr and main's frame pointer
// so the solver can compute the exact return address location at runtime.
void debug_info(void *fake_chunk_addr, void *main_frame_addr) {
    puts("\n=== Debug Information ===");
    printf("print_flag function: %p\n", print_flag);
    printf("Main fake chunk: %p (size field at %p)\n",
           (char*)fake_chunk_addr + 16, (char*)fake_chunk_addr + 8);
    // main's saved RIP is exactly at main_rbp + 8
    printf("Return address location: %p\n", (char*)main_frame_addr + 8);
    printf("Hint: malloc(0x1a0) expects chunks with size 0x1b1\n");
    printf("Challenge: Use House of Spirit to call print_flag()!\n");
    puts("=========================");
}

void advanced_edit() {
    printf("Index: ");
    int idx;
    if (scanf("%d", &idx) != 1) return;
    getchar();
    if (idx < 0 || idx >= item_count || !items[idx]) {
        puts("[-] Invalid index!");
        return;
    }
    printf("New data pointer (hex): ");
    unsigned long ptr;
    if (scanf("%lx", &ptr) == 1) {
        items[idx]->data = (char*)ptr;
        puts("[+] Pointer updated");
    }
    getchar();
}

void menu() {
    puts("1. Add item");
    puts("2. View item");
    puts("3. Edit item");
    puts("4. Delete item");
    puts("5. Debug info");
    puts("6. Advanced edit (pointer)");
    puts("7. Exit");
    printf("> ");
}

int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    banner();

    // Fake chunk on main's stack with valid size for 0x1a0-byte malloc requests
    long potential_fake_chunk[20];
    memset(potential_fake_chunk, 0, sizeof(potential_fake_chunk));
    potential_fake_chunk[1] = 0x1b1;  // valid tcache size field

    int choice;
    while (1) {
        menu();
        if (scanf("%d", &choice) != 1) break;
        getchar();

        switch (choice) {
            case 1: add_item(); break;
            case 2: view_item(); break;
            case 3: edit_item(); break;
            case 4: delete_item(); break;
            // Pass both fake chunk addr AND main's frame pointer
            case 5: debug_info(potential_fake_chunk,
                               __builtin_frame_address(0)); break;
            case 6: advanced_edit(); break;
            case 7: puts("Goodbye!"); return 0;
            default: puts("[-] Invalid choice!");
        }
        puts("");
    }
    return 0;
}