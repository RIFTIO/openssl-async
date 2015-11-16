typedef struct ERR_string_data_st {
        unsigned long error;
        const char *string;
} ERR_STRING_DATA;



int ERR_get_next_error_library(void)
{
    return 1;
}

void ERR_load_strings(int lib, ERR_STRING_DATA *str)
{
    return;
}

void ERR_unload_strings(int lib, ERR_STRING_DATA *str)
{
    return;
}

void ERR_put_error(int lib, int func, int reason, const char *file, int line)
{
    return;
}

void ERR_clear_error(void)
{
    return;
}

