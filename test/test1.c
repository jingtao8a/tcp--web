#include <stdio.h>
#include <stdint.h>

#pragma pack(1)
union test {
    struct {
        uint8_t a : 4;
        uint8_t b : 4;
        uint8_t c : 4;
        uint8_t d : 4;
    };
    uint16_t all;
};
#pragma pack()
int main() {
    union test obj;
    obj.a = 0;
    obj.b = 0;
    obj.c = 1;
    obj.d = 0;
    printf("%d", obj.all);
    return 0;
}