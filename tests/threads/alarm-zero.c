/* Tests timer_sleep(0), which should return immediately. */

#include <stdio.h>

#include "devices/timer.h"
#include "tests/threads/tests.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"

void test_alarm_zero( void ) {
    timer_sleep( 0 );
    pass();
}
