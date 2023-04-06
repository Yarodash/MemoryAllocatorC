#include "memory_manage.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>

typedef struct FreeBlockHeader {
    size_t size;
    void* next;
    void* prev;
} FreeBlockHeader;

typedef struct BusyBlockHeader {
    size_t size;
} BusyBlockHeader;

typedef struct Footer {
    size_t size;
} Footer;

#define PAGE_ALIGNMENT 4096
#define BLOCK_ALIGNMENT 4

#define FREE_BLOCK_HEADER_SIZE sizeof(FreeBlockHeader)
#define BUSY_BLOCK_HEADER_SIZE sizeof(BusyBlockHeader)
#define BLOCK_FOOTER_SIZE sizeof(Footer)

#define FREE_BLOCK_META_SIZE (FREE_BLOCK_HEADER_SIZE + BLOCK_FOOTER_SIZE)
#define BUSY_BLOCK_META_SIZE (BUSY_BLOCK_HEADER_SIZE + BLOCK_FOOTER_SIZE)

#define GET_FREE_FOOTER(header) ((Footer*)((void*)header + BLOCK_SIZE(header->size) - BLOCK_FOOTER_SIZE))

#define FREE_FLAG ((unsigned long long)0x1)
#define IS_FREE(size) (((size) & FREE_FLAG) == FREE_FLAG)
#define SET_FREE(size) size |= FREE_FLAG
#define SET_BUSY(size) size &= ~FREE_FLAG
#define BLOCK_SIZE(size) (size & ~FREE_FLAG)

#define ALIGN(x, y) (((x)+((y)-1))&~((y)-1))
#define ALIGN_PAGE(x) ALIGN((x), PAGE_ALIGNMENT)
#define ALIGN_BLOCK(x) ALIGN((x), BLOCK_ALIGNMENT)

static void* malloc_start = NULL;
static void* malloc_end = NULL;
static void* first_free_block_ptr = NULL;

static size_t MAX(size_t a, size_t b) {
    return a > b ? a : b;
}

static FreeBlockHeader* get_left_free_block(FreeBlockHeader* free_header) {
    if (free_header == malloc_start) {
        return NULL;
    }

    size_t left_block_size = BLOCK_SIZE(*(size_t*)((void*)free_header - sizeof(size_t)));

    FreeBlockHeader* left_block = (void*)free_header - left_block_size;

    if (IS_FREE(left_block->size)) {
        return left_block;
    }

    return NULL;
}

static FreeBlockHeader* get_right_free_block(FreeBlockHeader* free_header) {
    FreeBlockHeader* right_block = (void*)free_header + BLOCK_SIZE(free_header->size);

    if (right_block == malloc_end) {
        return NULL;
    }

    if (IS_FREE(right_block->size)) {
        return right_block;
    }

    return NULL;
}

static FreeBlockHeader* get_last_free_block() {
    return get_left_free_block(malloc_end);
}

static void combine_left(FreeBlockHeader* left_header, FreeBlockHeader* free_header) {
    assert(free_header == first_free_block_ptr);    

    left_header->size = BLOCK_SIZE(left_header->size) + BLOCK_SIZE(free_header->size);
    SET_FREE(left_header->size);
    GET_FREE_FOOTER(left_header)->size = left_header->size;

    FreeBlockHeader* prev_header = (FreeBlockHeader*)left_header->prev;
    FreeBlockHeader* next_header = (FreeBlockHeader*)left_header->next;

    FreeBlockHeader* second_header = (FreeBlockHeader*)free_header->next;
    assert(second_header != NULL);

    if (second_header != left_header) {
        assert(prev_header != free_header);

        prev_header->next = next_header;
        if (next_header != NULL) {
            next_header->prev = prev_header;
        }

        first_free_block_ptr = left_header;
        left_header->prev = NULL;

        left_header->next = free_header->next;
        second_header->prev = left_header;
    }
    else 
    {
        assert(prev_header == free_header);

        first_free_block_ptr = left_header;
        left_header->prev = NULL;
    }
}

static void combine_right(FreeBlockHeader* free_header, FreeBlockHeader* right_header) {
    assert(free_header == first_free_block_ptr);

    free_header->size = BLOCK_SIZE(free_header->size) + BLOCK_SIZE(right_header->size);
    SET_FREE(free_header->size);
    GET_FREE_FOOTER(free_header)->size = free_header->size;

    FreeBlockHeader* prev_header = (FreeBlockHeader*)right_header->prev;
    FreeBlockHeader* next_header = (FreeBlockHeader*)right_header->next;

    FreeBlockHeader* second_header = (FreeBlockHeader*)free_header->next;
    assert(second_header != NULL);

    if (second_header != right_header) {
        prev_header->next = next_header;
        if (next_header != NULL) {
            next_header->prev = prev_header;
        }
    }
    else 
    {
        assert(prev_header == free_header);

        free_header->next = right_header->next;
        if (next_header != NULL) {
            next_header->prev = free_header;
        }
    }
}

static void* find(size_t size) {
    FreeBlockHeader* current_free_block = (FreeBlockHeader*)first_free_block_ptr;

    while (current_free_block != NULL) {
        size_t current_free_block_size = BLOCK_SIZE(current_free_block->size);

        if (current_free_block_size - BUSY_BLOCK_META_SIZE >= size) {

            size_t min_used_space = MAX(size + BUSY_BLOCK_META_SIZE, FREE_BLOCK_META_SIZE);

            size_t space_left = current_free_block_size - min_used_space;
            if (space_left <= FREE_BLOCK_META_SIZE) {
                space_left = 0;
            }
            size_t used_space = current_free_block_size - space_left;

            FreeBlockHeader* prev_free_block = (FreeBlockHeader*) current_free_block->prev;
            FreeBlockHeader* next_free_block = (FreeBlockHeader*) current_free_block->next;

            if (space_left == 0) {
                if (prev_free_block != NULL) {
                    prev_free_block->next = next_free_block;
                }

                if (next_free_block != NULL) {
                    next_free_block->prev = prev_free_block;
                }

                if (first_free_block_ptr == current_free_block) {
                    first_free_block_ptr = current_free_block->next;
                }
            } 
            else 
            {
                FreeBlockHeader* new_free_block_header = (FreeBlockHeader*) ((void*)current_free_block + used_space);
                Footer* new_free_block_footer = (Footer*) ((void*)current_free_block + current_free_block_size - BLOCK_FOOTER_SIZE);

                if (prev_free_block != NULL) {
                    prev_free_block->next = new_free_block_header;
                }

                if (next_free_block != NULL) {
                    next_free_block->prev = new_free_block_header;
                }

                new_free_block_header->prev = current_free_block->prev;
                new_free_block_header->next = current_free_block->next;

                new_free_block_header->size = space_left;
                new_free_block_footer->size = space_left;
                SET_FREE(new_free_block_header->size);
                SET_FREE(new_free_block_footer->size);

                if (first_free_block_ptr == current_free_block) {
                    first_free_block_ptr = new_free_block_header;
                }
            }

            BusyBlockHeader* busy_header = (BusyBlockHeader*) current_free_block;
            Footer* busy_footer = (Footer*) ((void*)current_free_block + used_space - BLOCK_FOOTER_SIZE);

            busy_header->size = used_space;
            busy_footer->size = used_space;
            SET_BUSY(busy_header->size);
            SET_BUSY(busy_footer->size);

            return (void*)current_free_block + BUSY_BLOCK_HEADER_SIZE;
        }

        current_free_block = (FreeBlockHeader*)current_free_block->next;
    }

    return NULL;
}

static void* create_new_free_block(size_t size_page_align) {
    void* new_free_block_ptr = sbrk(size_page_align);

    if (new_free_block_ptr == (void*)-1) {
        return NULL;
    }

    if (malloc_start == NULL) {
        malloc_start = new_free_block_ptr;
    }
    malloc_end = new_free_block_ptr + size_page_align;

    FreeBlockHeader* free_block_header = (FreeBlockHeader*)new_free_block_ptr;
    free_block_header->size = size_page_align;
    SET_FREE(free_block_header->size);
    free_block_header->next = first_free_block_ptr;
    free_block_header->prev = NULL;

    GET_FREE_FOOTER(free_block_header)->size = free_block_header->size;

    if (first_free_block_ptr != NULL) {
        FreeBlockHeader* next_free_block = (FreeBlockHeader*) first_free_block_ptr;
        next_free_block->prev = free_block_header;
    }

    first_free_block_ptr = new_free_block_ptr;

    FreeBlockHeader* last_header = get_left_free_block(new_free_block_ptr);
    if (last_header != NULL) {
        combine_left(last_header, new_free_block_ptr);
    }

    return (void*)1;
}

void* mem_alloc(size_t size) {
    size = ALIGN_BLOCK(size);

    if (first_free_block_ptr == NULL) {
        size_t size_page_align = ALIGN_PAGE(size + FREE_BLOCK_META_SIZE);

        void* allocation_result = create_new_free_block(size_page_align);

        if (allocation_result == NULL) {
            return NULL;
        }
    }

    void* found = find(size);

    if (found != NULL) {
        return found;
    }

    FreeBlockHeader* last_block = get_last_free_block();

    size_t need_space;
    
    if (last_block != NULL) {
        need_space = size - last_block->size + BUSY_BLOCK_META_SIZE;
    } else {
        need_space = MAX(size + BUSY_BLOCK_META_SIZE, FREE_BLOCK_META_SIZE);
    }

    assert(need_space > 0);

    size_t size_page_align = ALIGN_PAGE(need_space);

    void* allocation_result = create_new_free_block(size_page_align);

    if (allocation_result == NULL) {
        return NULL;
    }

    void* result = find(size);
    assert(result != NULL);
    return result;
}

void mem_free(void* ptr) {
    if (ptr < malloc_start + BUSY_BLOCK_HEADER_SIZE || ptr >= malloc_end || ptr == NULL) return;

    FreeBlockHeader* free_header = (FreeBlockHeader*)(ptr - BUSY_BLOCK_HEADER_SIZE);
    Footer* free_footer = GET_FREE_FOOTER(free_header);

    assert(BLOCK_SIZE(free_header->size) >= 32);
    assert(free_header->size == free_footer->size);

    SET_FREE(free_header->size);
    SET_FREE(free_footer->size);

    FreeBlockHeader* left_header = get_left_free_block(free_header);
    FreeBlockHeader* right_header = get_right_free_block(free_header);

    free_header->next = first_free_block_ptr;
    free_header->prev = NULL;
    if (first_free_block_ptr != NULL) {
        ((FreeBlockHeader*)first_free_block_ptr)->prev = free_header;
    }
    first_free_block_ptr = free_header;

    if (left_header != NULL && right_header == NULL) 
    {
        combine_left(left_header, free_header);   
    } 
    else if (left_header == NULL && right_header != NULL) 
    {
        combine_right(free_header, right_header);
    }
    else if (left_header != NULL && right_header != NULL) 
    {
        combine_left(left_header, free_header);
        combine_right(left_header, right_header);
    }
}

void clear_heap() {
    if (malloc_start != NULL) {
        sbrk(malloc_start - malloc_end);
    }
    
    malloc_start = NULL;
    malloc_end = NULL;
    first_free_block_ptr = NULL;
}

size_t malloc_usable_size(void* ptr) {
    if (ptr < malloc_start + BUSY_BLOCK_HEADER_SIZE || ptr >= malloc_end || ptr == NULL) return 0;

    BusyBlockHeader* busy_header = (BusyBlockHeader*)(ptr - BUSY_BLOCK_HEADER_SIZE);

    assert(!IS_FREE(busy_header->size));

    return busy_header->size - BUSY_BLOCK_META_SIZE;
}

void* mem_realloc(void* ptr, size_t size) {
    if (size == 0) {
        mem_free(ptr);
        return NULL;
    }

    if (ptr == NULL) {
        return mem_alloc(size);
    }

    void* new_ptr = mem_alloc(size);
    if (new_ptr == NULL) {
        return NULL;
    }

    size_t old_size = malloc_usable_size(ptr);
    if (size < old_size) {
        old_size = size;
    }

    memcpy(new_ptr, ptr, old_size);
    mem_free(ptr);

    return new_ptr;
}

void mem_show() {
    void* block = malloc_start;

    size_t _free = 0;
    size_t count = 0;

    while (block < malloc_end) {
        FreeBlockHeader* header = (FreeBlockHeader*)block;
        printf("0x%lx | size: %6d %1d -> 0x%lx", header, BLOCK_SIZE(header->size), IS_FREE(header->size), block + BLOCK_SIZE(header->size));

        if (IS_FREE(header->size)) {
            printf(" PREV: 0x%016lx NEXT: 0x%016lx\n", header->prev, header->next);
        } else {
            printf("\n");
        }

        _free += BLOCK_SIZE(header->size) * IS_FREE(header->size);
        block += BLOCK_SIZE(header->size);
        count += IS_FREE(header->size);
    }

    printf("FREE MEMORY: %8d\n", _free);
    printf("FREE BLOCKS: %8d\n", count);
}
