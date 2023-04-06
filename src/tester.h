#include <stdio.h>
#include <assert.h>

#include "memory_manage.h"

#define MAX_ALLOC_COUNT 256

static void* ptr_used[MAX_ALLOC_COUNT];
static size_t size_used[MAX_ALLOC_COUNT];
static int counter = 0;

size_t random_mask() {
    int r = rand() & 15;
    if (r < 3) return 0xf;
    if (r < 10) return 0xff;
    if (r < 15) return 0xfff;
    return 0xffff;
}

size_t random_size() {
    return (rand() & random_mask()) | 1;
}

void allocate_one() {
    if (counter == MAX_ALLOC_COUNT) return;

    size_t size = random_size();
    void* ptr = mem_alloc(size);
    assert(ptr != NULL);

    //printf("allocate %5d -> 0x%lx\n", size, ptr);

    ptr_used[counter] = ptr;
    size_used[counter] = size;
    counter++;
}

void shift(int q) {
    for (int i = q; i < counter - 1; i++) {
        ptr_used[i] = ptr_used[i+1];
        size_used[i] = size_used[i+1];
    }
    counter--;
}

void free_one() {
    if (counter == 0) return;

    int q = rand() % counter;
    void* ptr = ptr_used[q];
    size_t size = size_used[q];

    //printf("free     %5d -> 0x%lx\n", size, ptr);

    mem_free(ptr);
    shift(q);
}

void realloc_one() {
    if (counter == 0) return;

    char old_memory[0xffff];

    int q = rand() % counter;
    void* ptr = ptr_used[q];
    size_t size = size_used[q];

    for (size_t x = 0; x < size; x++) {
        char* byte_location = ptr + x;
        old_memory[x] = *byte_location;
    }

    size_t new_size = random_size();
    
    void* new_ptr = mem_realloc(ptr, new_size);

    assert(new_ptr != NULL);
    assert(new_ptr != ptr);

    ptr_used[q] = new_ptr;
    size_used[q] = new_size;

    size_t smaller = (size < new_size ? size : new_size);
    for (size_t x = 0; x < smaller; x++) {
        char* byte_location_new = new_ptr + x;
        assert(old_memory[x] == *byte_location_new);
    }

    //printf("realloc  %5d -> 0x%lx from %d -> 0x%lx\n", new_size, new_ptr, size, ptr);
}

void check_all() {
    for (int i = 0; i < counter; i++) {
        void* ptr = ptr_used[i];
        size_t size = size_used[i];

        for (size_t x = 0; x < size; x++) {
            char* byte_location = ptr + x;
            *byte_location = (i & 127);
        }
    }

    for (int i = 0; i < counter; i++) {
        void* ptr = ptr_used[i];
        size_t size = size_used[i];

        for (size_t x = 0; x < size; x++) {
            char* byte_location = ptr + x;
            assert(*byte_location == (i & 127));
        }
    }

    //printf("CHECK DONE\n");
}

void random_action() {
    int action = rand() & 15;

    if (action < 3) {
        allocate_one();
    }
    else if (action < 6) {
        free_one();
    }
    else if (action < 15) {
        realloc_one();
    }
    else if (action == 15) {
        check_all();
    }
}

void clear() {
    counter = 0;
}

void run_test() {
    
    for (int j = 0; j < 10000; j++) {
        clear_heap();
        clear();
        printf("J = %d\n", j);
        srand(j);

        for (int i = 0; i < 2048; i++) {
            random_action();
        }    

        mem_show();
    }

}
