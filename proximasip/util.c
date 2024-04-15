#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

size_t plength(void *nth, void *zeroth);
size_t plenmax(void *nth, void *zeroth, size_t max);

size_t
plenmax(void *nth, void *zeroth, size_t max)
{
        size_t len = (nth - zeroth);

        if (len > max) {
                abort();
        }

        return (len);
}       

size_t
plength(void *nth, void *zeroth)
{
        return (plenmax(nth, zeroth, 65536));   /* a sizeable packet max? */
}

