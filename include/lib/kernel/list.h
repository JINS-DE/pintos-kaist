#ifndef __LIB_KERNEL_LIST_H
#define __LIB_KERNEL_LIST_H

/* 이중 연결 리스트.
 *
 * 이 이중 연결 리스트 구현은 동적 할당된 메모리를 필요로 하지 않습니다.
 * 대신, 리스트의 잠재적 요소가 될 각 구조체는 `struct list_elem` 멤버를 포함해야 합니다.
 * 모든 리스트 함수는 이러한 `struct list_elem`들에 대해 동작합니다.
 * list_entry 매크로는 `struct list_elem`을 다시 그것을 포함하는 구조체로 변환할 수 있게 해줍니다.

 * 예를 들어, `struct foo`의 리스트가 필요하다고 가정해 봅시다.
 * `struct foo`는 다음과 같이 `struct list_elem` 멤버를 포함해야 합니다:

 * struct foo {
 *   struct list_elem elem;
 *   int bar;
 *   ...다른 멤버들...
 * };

 * 그 다음, `struct foo`의 리스트를 다음과 같이 선언하고 초기화할 수 있습니다:

 * struct list foo_list;

 * list_init (&foo_list);

 * 반복(iteration)은 `struct list_elem`에서 다시 그것을 포함하는 구조체로 변환할 필요가 있는 일반적인 상황입니다.
 * 다음은 foo_list를 사용하는 예시입니다:

 * struct list_elem *e;

 * for (e = list_begin (&foo_list); e != list_end (&foo_list);
 * e = list_next (e)) {
 *   struct foo *f = list_entry (e, struct foo, elem);
 *   ...f와 관련된 작업을 수행...
 * }

 * 리스트 사용에 대한 실제 예시는 소스 코드에서 찾을 수 있습니다. 예를 들어,
 * threads 디렉토리의 malloc.c, palloc.c, 그리고 thread.c가 모두 리스트를 사용합니다.

 * 이 리스트 인터페이스는 C++ STL의 list<> 템플릿에서 영감을 받았습니다.
 * list<>에 익숙하다면 이를 쉽게 사용할 수 있을 것입니다. 하지만 이러한 리스트는
 * 타입 검사를 *전혀* 하지 않으며, 다른 많은 올바름 검사도 수행할 수 없다는 점을 강조해야 합니다.
 * 만약 잘못 사용하면 오류가 발생할 것입니다.

 * 리스트 용어 설명:

 * - "front": 리스트의 첫 번째 요소. 리스트가 비어있을 때는 정의되지 않습니다.
 * list_front()로 반환됩니다.

 * - "back": 리스트의 마지막 요소. 리스트가 비어있을 때는 정의되지 않습니다.
 * list_back()로 반환됩니다.

 * - "tail": 리스트의 마지막 요소 바로 다음에 있는 요소를 의미합니다.
 * 리스트가 비어있어도 잘 정의되어 있습니다. list_end()로 반환됩니다.
 * 앞에서 뒤로 반복할 때 종료 시점으로 사용됩니다.

 * - "beginning": 비어 있지 않은 리스트의 경우 첫 번째 요소, 비어 있는 리스트의 경우
 * 마지막 요소를 의미합니다. list_begin()으로 반환됩니다. 앞에서 뒤로 반복할 때 시작점으로 사용됩니다.

 * - "head": 리스트의 첫 번째 요소 바로 앞에 있는 요소를 의미합니다.
 * 리스트가 비어있어도 잘 정의되어 있습니다. list_rend()로 반환됩니다.
 * 뒤에서 앞으로 반복할 때 종료 시점으로 사용됩니다.

 * - "reverse beginning": 비어 있지 않은 리스트의 경우 마지막 요소, 비어 있는 리스트의 경우
 * 첫 번째 요소를 의미합니다. list_rbegin()으로 반환됩니다. 뒤에서 앞으로 반복할 때 시작점으로 사용됩니다.

 * - "interior element": 리스트의 첫 번째 또는 마지막 요소가 아닌 실제 리스트 요소를 의미합니다.
 * 비어 있는 리스트는 내부 요소를 가지고 있지 않습니다.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* List element. */
struct list_elem {
	struct list_elem *prev;     /* Previous list element. */
	struct list_elem *next;     /* Next list element. */
};

/* List. */
struct list {
	struct list_elem head;      /* List head. */
	struct list_elem tail;      /* List tail. */
};

/* 포인터 LIST_ELEM을 해당 리스트 요소가 포함된 구조체의 포인터로 변환합니다.
   외부 구조체의 이름 STRUCT와 리스트 요소의 멤버 이름 MEMBER를 제공해야 합니다.
   파일 상단의 큰 주석에서 예시를 참조하세요. */

#define list_entry(LIST_ELEM, STRUCT, MEMBER)           \
	((STRUCT *) ((uint8_t *) &(LIST_ELEM)->next     \
		- offsetof (STRUCT, MEMBER.next)))

void list_init (struct list *);

/* List traversal. */
struct list_elem *list_begin (struct list *);
struct list_elem *list_next (struct list_elem *);
struct list_elem *list_end (struct list *);

struct list_elem *list_rbegin (struct list *);
struct list_elem *list_prev (struct list_elem *);
struct list_elem *list_rend (struct list *);

struct list_elem *list_head (struct list *);
struct list_elem *list_tail (struct list *);

/* List insertion. */
void list_insert (struct list_elem *, struct list_elem *);
void list_splice (struct list_elem *before,
		struct list_elem *first, struct list_elem *last);
void list_push_front (struct list *, struct list_elem *);
void list_push_back (struct list *, struct list_elem *);

/* List removal. */
struct list_elem *list_remove (struct list_elem *);
struct list_elem *list_pop_front (struct list *);
struct list_elem *list_pop_back (struct list *);

/* List elements. */
struct list_elem *list_front (struct list *);
struct list_elem *list_back (struct list *);

/* List properties. */
size_t list_size (struct list *);
bool list_empty (struct list *);

/* Miscellaneous. */
void list_reverse (struct list *);

/* Compares the value of two list elements A and B, given
   auxiliary data AUX.  Returns true if A is less than B, or
   false if A is greater than or equal to B. */
typedef bool list_less_func (const struct list_elem *a,
                             const struct list_elem *b,
                             void *aux);

/* Operations on lists with ordered elements. */
void list_sort (struct list *,
                list_less_func *, void *aux);
void list_insert_ordered (struct list *, struct list_elem *,
                          list_less_func *, void *aux);
void list_unique (struct list *, struct list *duplicates,
                  list_less_func *, void *aux);

/* Max and min. */
struct list_elem *list_max (struct list *, list_less_func *, void *aux);
struct list_elem *list_min (struct list *, list_less_func *, void *aux);

#endif /* lib/kernel/list.h */
